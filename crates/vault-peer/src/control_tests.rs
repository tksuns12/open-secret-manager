//! Vaults coupled to a real control plane: OpenRaft nodes with SQLite
//! storage on an in-process network, pairing messages through the real
//! frame encoding, and revisions exchanged by sync sessions.

use std::{sync::Arc, time::Duration};

use openraft::Config;
use osm_vault_core::{Item, Vault};
use osm_vault_membership::{
    device_id_from_bytes, ControlNode, ControlState, DeviceId, NodeOptions, Router,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tempfile::TempDir;

use crate::{
    approve_enrollment,
    control::{self, Reconciled},
    invite, review_join,
    tests::{address, login, over_wire, sync, JOINER_PIN, NOW},
    EnrollmentGrant, Error, Invitation, Joiner, PeerStore,
};

const PASSWORD: &str = "member password";

fn fast_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "test".into(),
            heartbeat_interval: 50,
            election_timeout_min: 300,
            election_timeout_max: 600,
            ..Config::default()
        }
        .validate()
        .unwrap(),
    )
}

struct Member {
    vault: Vault,
    peers: PeerStore,
    invitations: InvitationStore,
    node: ControlNode,
}

impl Member {
    fn id(&self) -> DeviceId {
        device_id_from_bytes(self.vault.device_id().unwrap())
    }

    fn state(&self) -> ControlState {
        self.node.state()
    }

    fn reconcile(&mut self) -> Reconciled {
        control::reconcile(&mut self.vault, &self.node.state()).unwrap()
    }

    /// Grants every enrolled voter the keys it lacks.
    async fn grant_keys(&self) {
        for request in control::grant_requests(&self.vault, &self.state()).unwrap() {
            control::submit(&self.node, request).await.unwrap();
        }
    }
}

/// Polls until `condition` holds.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..400 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting until {what}");
}

/// Devices on one in-process control-plane network.
struct Net {
    dir: TempDir,
    router: Router,
}

impl Net {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            router: Router::default(),
        }
    }

    async fn node(&self, name: &str, device: DeviceId, vault_id: [u8; 32]) -> ControlNode {
        let node = ControlNode::start(
            self.dir.path().join(format!("{name}.raft")),
            device,
            vault_id,
            self.router.network(device),
            NodeOptions {
                config: fast_config(),
                write_timeout: Duration::from_secs(3),
                forwarder: Some(self.router.forwarder(device)),
                ..NodeOptions::default()
            },
        )
        .await
        .unwrap();
        self.router.register(device, node.raft().clone());
        node
    }

    /// Creates a vault and founds its control plane with it as sole voter.
    async fn found(&self, name: &str) -> Member {
        let (vault, _) =
            Vault::create(self.dir.path().join(format!("{name}.db")), PASSWORD).unwrap();
        let mut peers = PeerStore::open_in_memory().unwrap();
        let device = device_id_from_bytes(vault.device_id().unwrap());
        let node = self.node(name, device, vault.vault_id()).await;
        control::found(&vault, &mut peers, &node).await.unwrap();
        Member {
            vault,
            peers,
            invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
            node,
        }
    }

    /// Pairs a new device with `inviter` up to the committed enrollment
    /// proposal. With `online`, the joiner's node is running, so the leader
    /// can bring it up to date.
    async fn propose(
        &self,
        inviter: &mut Member,
        name: &str,
        online: bool,
    ) -> (Joiner, EnrollmentGrant, Option<ControlNode>) {
        let invitation = invite(
            &inviter.vault,
            &mut inviter.invitations,
            &mut inviter.peers,
            address(),
            NOW,
            300,
        )
        .unwrap();
        let code = invitation.encode().unwrap();
        let (joiner, request) =
            Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW + 1).unwrap();
        let node = if online {
            Some(
                self.node(name, joiner.control_device(), joiner.vault_id())
                    .await,
            )
        } else {
            None
        };
        let review = review_join(
            &inviter.vault,
            &inviter.invitations,
            &mut inviter.peers,
            over_wire(&request),
            NOW + 2,
        )
        .unwrap();
        assert_eq!(review.sas(), joiner.sas());
        let (proposal, grant) =
            approve_enrollment(&inviter.vault, &mut inviter.invitations, review, NOW + 3).unwrap();
        control::submit(&inviter.node, proposal).await.unwrap();
        (joiner, over_wire(&grant), node)
    }

    /// Runs a full enrollment through `inviter`: proposal, catch-up, voter,
    /// key grant, and the joiner's vault.
    async fn enroll(&self, inviter: &mut Member, name: &str) -> Member {
        let (joiner, grant, node) = self.propose(inviter, name, true).await;
        let node = node.unwrap();
        let device = joiner.control_device();
        until("the joiner is a voter", || {
            inviter.state().is_settled_member(device)
        })
        .await;
        inviter.grant_keys().await;
        until("the joiner holds every key", || {
            joiner.enrolled(&node.state())
        })
        .await;
        let vault = joiner
            .finish_enrollment(
                &grant,
                true,
                &node.state(),
                self.dir.path().join(format!("{name}.db")),
                PASSWORD,
            )
            .unwrap();
        Member {
            vault,
            peers: PeerStore::open_in_memory().unwrap(),
            invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
            node,
        }
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

fn epochs(vault: &Vault) -> Vec<u64> {
    vault
        .epoch_keys()
        .unwrap()
        .into_iter()
        .map(|(epoch, _)| epoch)
        .collect()
}

fn edited(item: &Item, password: &str) -> Item {
    let mut item = item.clone();
    item.password = password.into();
    item
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_join_through_the_control_plane_beyond_two() {
    let net = Net::new();
    let mut a = net.found("a").await;
    a.vault.put(login("From A", "a-secret")).unwrap();
    let mut b = net.enroll(&mut a, "b").await;
    // B invites the third device; its proposal is forwarded to the leader.
    let mut c = net.enroll(&mut b, "c").await;
    for member in [&a, &b, &c] {
        let state = member.state();
        assert_eq!(state.voters().len(), 3);
        assert_eq!(state.missing_epochs(member.id()), Vec::<u64>::new());
    }
    // Joined devices hold the vault's epoch keys under their own roots.
    assert_eq!(epochs(&c.vault), vec![1]);
    assert_eq!(c.vault.current_epoch(), 1);

    sync(&mut a.vault, &mut b.vault);
    sync(&mut b.vault, &mut c.vault);
    assert_eq!(titles(&c.vault), vec!["From A"]);

    // C's edit reaches A before A has caught up with C's enrollment: it is
    // held, then applied as-is once A reconciles.
    c.vault.put(login("From C", "c-secret")).unwrap();
    let (report, _) = sync(&mut a.vault, &mut c.vault);
    assert_eq!(report.quarantined, 1);
    let reconciled = a.reconcile();
    assert_eq!(reconciled.authorized, 2);
    assert_eq!(reconciled.released, 1);
    assert!(a.vault.quarantined().unwrap().is_empty());
    assert_eq!(titles(&a.vault), vec!["From A", "From C"]);
    // Reconciling again changes nothing.
    assert_eq!(a.reconcile(), Reconciled::default());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removal_rotates_the_epoch_for_the_remaining_devices_only() {
    let net = Net::new();
    let mut a = net.found("a").await;
    let item = login("Shared", "v1");
    let base = a.vault.put(item.clone()).unwrap().revision;
    let mut b = net.enroll(&mut a, "b").await;
    let mut c = net.enroll(&mut a, "c").await;
    for member in [&mut a, &mut b, &mut c] {
        member.reconcile();
    }
    sync(&mut a.vault, &mut b.vault);
    sync(&mut a.vault, &mut c.vault);
    // C's last edit before removal is accepted everywhere.
    c.vault.update(edited(&item, "from C"), &base).unwrap();
    sync(&mut c.vault, &mut a.vault);
    sync(&mut a.vault, &mut b.vault);

    // B is locked when the removal happens.
    b.vault.lock();
    let removal =
        control::removal_request(&a.vault, &a.state(), c.vault.device_id().unwrap()).unwrap();
    control::submit(&a.node, removal).await.unwrap();
    until("the removal completes", || {
        [&a, &b]
            .iter()
            .all(|member| member.state().epoch == 2 && member.state().pending.is_none())
    })
    .await;

    // A, which removed C, takes the new epoch and endorses C's last edit.
    let reconciled = a.reconcile();
    assert_eq!(reconciled.installed, vec![2]);
    assert_eq!(reconciled.activated, Some(2));
    assert_eq!(reconciled.revoked, 1);
    assert_eq!(reconciled.endorsed, 1);
    a.vault.put(login("After removal", "new secret")).unwrap();
    assert!(a
        .vault
        .encrypted_revisions()
        .unwrap()
        .iter()
        .rev()
        .take(2)
        .all(|revision| revision.key_epoch == 2));

    // Locked, B can only stop writing under the old epoch; after unlock it
    // must reconcile before it can write again.
    let reconciled = b.reconcile();
    assert!(reconciled.installed.is_empty());
    assert_eq!(b.vault.write_fence(), 2);
    b.vault.unlock(PASSWORD).unwrap();
    assert!(matches!(
        b.vault.put(login("Too early", "x")),
        Err(osm_vault_core::Error::EpochPending)
    ));
    assert_eq!(b.reconcile().activated, Some(2));
    b.vault.put(login("From B", "b-secret")).unwrap();

    // C never receives the new key: what A writes now stays unreadable to
    // it, waiting in its queue.
    assert_eq!(epochs(&c.vault), vec![1]);
    let (_, report) = sync(&mut a.vault, &mut c.vault);
    assert!(report.pending >= 2);
    assert!(!titles(&c.vault).contains(&"After removal".to_owned()));
    assert_eq!(c.vault.get(&item.id).unwrap().item.password, "from C");

    // What C writes after removal is held for review by the others.
    let head = c.vault.get(&item.id).unwrap().revision;
    c.vault
        .update(edited(&item, "after removal"), &head)
        .unwrap();
    let (report, _) = sync(&mut a.vault, &mut c.vault);
    assert_eq!(report.quarantined, 1);
    assert_eq!(a.vault.get(&item.id).unwrap().item.password, "from C");

    // B accepted C's edits before removal; A's endorsement only adds a
    // child, so nothing is held there.
    sync(&mut a.vault, &mut b.vault);
    assert!(b.vault.quarantined().unwrap().is_empty());
    assert_eq!(b.vault.get(&item.id).unwrap().item.password, "from C");

    // A device joining now receives both epochs, treats C as removed, and
    // still ends up with A's view of C's history.
    let mut d = net.enroll(&mut a, "d").await;
    assert_eq!(epochs(&d.vault), vec![1, 2]);
    assert_eq!(d.vault.current_epoch(), 2);
    assert_eq!(
        d.vault.revoked_devices().unwrap(),
        vec![c.vault.device_id().unwrap()]
    );
    sync(&mut a.vault, &mut d.vault);
    assert!(d.vault.quarantined().unwrap().is_empty());
    assert_eq!(d.vault.get(&item.id).unwrap().item.password, "from C");
    assert_eq!(titles(&d.vault), titles(&a.vault));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_takes_effect_only_once_a_quorum_completes_it() {
    let net = Net::new();
    let mut a = net.found("a").await;
    let mut b = net.enroll(&mut a, "b").await;
    let mut c = net.enroll(&mut a, "c").await;
    for member in [&mut a, &mut b, &mut c] {
        member.reconcile();
    }
    let c_device = c.vault.device_id().unwrap();

    // Without B and C nothing commits, and nothing changes on A.
    net.router.isolate(b.id());
    net.router.isolate(c.id());
    let removal = control::removal_request(&a.vault, &a.state(), c_device).unwrap();
    match control::submit(&a.node, removal.clone()).await {
        Err(Error::Membership(error)) => assert!(matches!(
            *error,
            osm_vault_membership::Error::QuorumUnavailable
        )),
        other => panic!("{other:?}"),
    }
    assert_eq!(a.state().epoch, 1);
    assert_eq!(a.reconcile(), Reconciled::default());
    a.vault.put(login("Still epoch 1", "x")).unwrap();

    // With C back but B still away, the proposal commits, but the change
    // needs B in the new configuration: it stays pending, and the new
    // epoch is not active anywhere.
    net.router.heal(c.id());
    control::submit(&a.node, removal.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    for member in [&a, &c] {
        let state = member.state();
        assert!(state.pending.is_some());
        assert_eq!(state.epoch, 1);
    }
    assert_eq!(a.reconcile(), Reconciled::default());
    assert_eq!(a.vault.write_fence(), 1);

    // Once B returns, the leader completes it; resubmitting the request
    // whose outcome was unknown is recognized, not a second rotation.
    net.router.heal(b.id());
    until("the removal completes", || {
        a.state().pending.is_none() && b.state().pending.is_none()
    })
    .await;
    assert!(a.node.submit(removal).await.unwrap().is_accepted());
    for member in [&a, &b] {
        assert_eq!(member.state().epoch, 2);
    }
    assert_eq!(a.reconcile().activated, Some(2));
    assert_eq!(b.reconcile().activated, Some(2));
    assert_eq!(epochs(&c.vault), vec![1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_enrollment_never_receives_keys() {
    let net = Net::new();
    let mut a = net.found("a").await;
    let mut b = net.enroll(&mut a, "b").await;
    b.reconcile();
    // The joiner never comes online to catch up.
    let (joiner, grant, _) = net.propose(&mut a, "j", false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(a.state().pending.is_some());
    assert!(!joiner.enrolled(&a.state()));

    let cancel = control::cancel_request(&b.vault, grant.request_id()).unwrap();
    control::submit(&b.node, cancel).await.unwrap();
    until("the cancellation completes", || {
        a.state().pending.is_none() && a.state().voters().len() == 2
    })
    .await;
    let state = a.state();
    assert!(control::grant_requests(&a.vault, &state)
        .unwrap()
        .is_empty());
    assert!(!state.authors.contains_key(&joiner.control_device()));
    assert!(matches!(
        joiner.finish_enrollment(&grant, true, &state, net.dir.path().join("j.db"), PASSWORD),
        Err(Error::EnrollmentPending)
    ));

    // The control plane can change again.
    let removal =
        control::removal_request(&a.vault, &a.state(), b.vault.device_id().unwrap()).unwrap();
    control::submit(&a.node, removal).await.unwrap();
    until("the removal completes", || a.state().epoch == 2).await;
    assert_eq!(a.reconcile().activated, Some(2));
}
