//! The control plane between devices over real TLS connections on
//! localhost. Each device has its own transport identity, listener, and
//! control-plane database; nothing is delivered in process.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use openraft::{
    raft::{AppendEntriesRequest, VoteRequest},
    Config, ServerState, Vote,
};
use osm_vault_core::Vault;
use osm_vault_membership::{
    device_id_from_bytes, ControlNode, ControlReply, ControlRequest, ControlRpc, ControlState,
    DeviceId, DeviceNode, Dialer, KeySigner, Link, MembershipChange, NodeOptions, Outcome,
    Rejection, Rotation, SignedRequest,
};
use osm_vault_sync::{
    seal_epoch_key, HpkeKeyPair, InvitationPolicy, InvitationStore, VaultId as SyncVaultId,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    control, control_tests::until, invite, serve_members, start_node, start_pairing, AddressBook,
    Error, MemberContact, MemberEndpoint, PairingListener, PeerStore,
};

const VAULT: [u8; 32] = [42; 32];
const NOW: u64 = 1_800_000_000;
const PASSWORD: &str = "member password";

/// Slower than the in-process tests use: a connection takes a TLS
/// handshake, and debug builds are slow.
fn tls_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "test".into(),
            heartbeat_interval: 100,
            election_timeout_min: 600,
            election_timeout_max: 1200,
            ..Config::default()
        }
        .validate()
        .unwrap(),
    )
}

fn options() -> NodeOptions {
    NodeOptions {
        config: tls_config(),
        write_timeout: Duration::from_secs(5),
        ..NodeOptions::default()
    }
}

/// A device's network side: its transport identity, its endpoint and
/// listener, and its control-plane node.
struct Host {
    id: DeviceId,
    peers: PeerStore,
    addresses: AddressBook,
    database: PathBuf,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    server: Option<JoinHandle<()>>,
}

impl Host {
    async fn start(dir: &TempDir, id: DeviceId, vault_id: [u8; 32]) -> Self {
        let mut peers = PeerStore::open_in_memory().unwrap();
        let addresses = AddressBook::default();
        let database = dir.path().join(format!("{id}.raft"));
        let (endpoint, node) = Self::node(&mut peers, &addresses, &database, id, vault_id).await;
        let mut host = Self {
            id,
            peers,
            addresses,
            database,
            endpoint,
            node,
            server: None,
        };
        host.listen().await;
        host
    }

    async fn node(
        peers: &mut PeerStore,
        addresses: &AddressBook,
        database: &PathBuf,
        id: DeviceId,
        vault_id: [u8; 32],
    ) -> (MemberEndpoint, Arc<ControlNode>) {
        let endpoint = MemberEndpoint::new(vault_id, peers, addresses.clone()).unwrap();
        let node = start_node(database, id, &endpoint, options())
            .await
            .unwrap();
        (endpoint, node)
    }

    /// Accepts connections on a new port.
    async fn listen(&mut self) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.endpoint
            .set_listen_port(listener.local_addr().unwrap().port());
        self.server = Some(tokio::spawn(serve_members(
            listener,
            self.endpoint.clone(),
            self.node.clone(),
        )));
    }

    /// Stops the device as a crash would. Its database, transport
    /// identity, and address book remain.
    async fn stop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
        self.node.shutdown().await;
    }

    /// Starts the stopped device again, without listening yet.
    async fn restart(&mut self, vault_id: [u8; 32]) {
        let (endpoint, node) = Self::node(
            &mut self.peers,
            &self.addresses,
            &self.database,
            self.id,
            vault_id,
        )
        .await;
        self.endpoint = endpoint;
        self.node = node;
    }

    fn pin(&self) -> [u8; 32] {
        self.endpoint.pin()
    }

    fn contact(&self) -> MemberContact {
        MemberContact {
            device_id: self.id.to_be_bytes(),
            transport_pin: self.pin(),
            address: self
                .endpoint
                .listen_port()
                .map(|port| format!("127.0.0.1:{port}")),
        }
    }

    fn state(&self) -> ControlState {
        self.node.state()
    }

    fn leads(&self) -> bool {
        let metrics = self.node.raft().metrics().borrow().clone();
        metrics.running_state.is_ok() && metrics.state == ServerState::Leader
    }
}

/// A device with signing and recipient keys but no vault: enough to
/// exercise the transport without deriving a vault key per device.
struct Bare {
    host: Host,
    key: SigningKey,
}

impl std::ops::Deref for Bare {
    type Target = Host;

    fn deref(&self) -> &Host {
        &self.host
    }
}

impl std::ops::DerefMut for Bare {
    fn deref_mut(&mut self) -> &mut Host {
        &mut self.host
    }
}

impl Bare {
    async fn start(dir: &TempDir, id: u8) -> Self {
        Self {
            host: Host::start(dir, DeviceId::from(id), VAULT).await,
            key: SigningKey::from_bytes(&[id; 32]),
        }
    }

    fn hpke(&self) -> HpkeKeyPair {
        HpkeKeyPair::from_secret(&[self.id as u8 + 50; 32])
    }

    fn info(&self) -> DeviceNode {
        DeviceNode {
            public_key: self.key.verifying_key().to_bytes(),
            transport_pin: self.pin(),
            recipient_key: self.hpke().public().as_bytes(),
        }
    }

    fn request(&self, id: u8, request: ControlRequest) -> SignedRequest {
        SignedRequest::sign(
            &VAULT,
            [id; 16],
            self.id,
            request,
            &KeySigner {
                device: self.id,
                key: self.key.clone(),
            },
        )
    }

    /// An epoch key for `epoch` sealed to this device.
    fn envelope(&self, epoch: u64) -> Vec<u8> {
        seal_epoch_key(
            SyncVaultId(VAULT),
            epoch,
            osm_vault_sync::DeviceId(self.info().public_key),
            self.hpke().public(),
            &[epoch as u8 + 100; 32],
        )
        .unwrap()
        .to_bytes()
        .to_vec()
    }

    /// Founds the control plane with this device as its only voter.
    async fn found(&self) {
        self.node
            .initialize([(self.id, self.info())].into())
            .await
            .unwrap();
        let genesis = self.request(
            0,
            ControlRequest::Genesis {
                epoch: 1,
                checks: vec![[201; 32]],
                authors: Vec::new(),
            },
        );
        assert_eq!(self.node.submit(genesis).await.unwrap(), Outcome::Accepted);
    }

    /// Enrolls `joiner` as pairing would: this device proposes it, and the
    /// joiner is told who the members are and announces itself to them.
    async fn enroll(&self, id: u8, joiner: &Bare, members: &[&Bare]) {
        let proposal = self.request(
            id,
            ControlRequest::ProposeChange(MembershipChange::Enroll {
                device: joiner.id,
                node: joiner.info(),
            }),
        );
        assert_eq!(self.node.submit(proposal).await.unwrap(), Outcome::Accepted);
        let contacts: Vec<MemberContact> = members.iter().map(|member| member.contact()).collect();
        joiner.endpoint.introduce(&contacts).unwrap();
        // A member accepts the joiner once it has applied the proposal.
        for member in members {
            for _ in 0..100 {
                if joiner
                    .endpoint
                    .announce(member.id, member.pin())
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        // Members that are away stay voters, so wait for the joiner
        // rather than for a particular voter set.
        let mut online: Vec<&Bare> = members.to_vec();
        online.push(joiner);
        until("the joiner is a member on every device", || {
            online
                .iter()
                .all(|device| device.state().is_settled_member(joiner.id))
        })
        .await;
    }

    fn removal(&self, id: u8, removed: &Bare, remaining: &[&Bare], epoch: u64) -> SignedRequest {
        self.request(
            id,
            ControlRequest::ProposeChange(MembershipChange::Remove {
                device: removed.id,
                rotation: Rotation {
                    epoch,
                    check: [epoch as u8 + 200; 32],
                    envelopes: remaining
                        .iter()
                        .map(|device| (device.id, device.envelope(epoch)))
                        .collect(),
                },
            }),
        )
    }
}

/// Waits until every device has applied a uniform membership of exactly
/// `voters` with no change pending.
async fn settle(devices: &[&Bare], voters: &BTreeSet<DeviceId>) {
    for _ in 0..800 {
        let settled = devices.iter().all(|device| {
            let state = device.state();
            state.pending.is_none() && state.is_uniform() && &state.voters() == voters
        });
        if settled {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let seen: Vec<_> = devices
        .iter()
        .map(|device| {
            let state = device.state();
            let metrics = device.node.raft().metrics().borrow().clone();
            (
                device.id,
                state.voters(),
                state.pending.is_some(),
                metrics.current_term,
                metrics.current_leader,
            )
        })
        .collect();
    panic!("membership did not settle on {voters:?}: {seen:?}");
}

async fn leader<'a>(devices: &[&'a Bare]) -> &'a Bare {
    for _ in 0..400 {
        if let Some(leader) = devices.iter().find(|device| device.leads()) {
            return leader;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no leader was elected");
}

/// Three devices in one control plane, founded by the first.
async fn three(dir: &TempDir) -> (Bare, Bare, Bare) {
    let a = Bare::start(dir, 1).await;
    let b = Bare::start(dir, 2).await;
    let c = Bare::start(dir, 3).await;
    a.found().await;
    a.enroll(1, &b, &[&a]).await;
    a.enroll(2, &c, &[&a, &b]).await;
    (a, b, c)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_plane_runs_between_devices_over_pinned_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, b, c) = three(&dir).await;
    for device in [&a, &b, &c] {
        assert_eq!(device.state().members(), BTreeSet::from([1, 2, 3]));
        assert_eq!(device.endpoint.roster().len(), 3);
    }
    // Every device learned where the others listen, first hand or from a
    // roster.
    for (device, others) in [(&a, [&b, &c]), (&b, [&a, &c]), (&c, [&a, &b])] {
        for other in others {
            assert_eq!(device.addresses.get(other.id), other.contact().address);
        }
    }

    // A follower's request reaches the leader over TLS.
    assert!(a.leads());
    let grant = b.request(
        10,
        ControlRequest::GrantKeys {
            device: b.id,
            envelopes: vec![b.envelope(1)],
        },
    );
    assert_eq!(b.node.submit(grant).await.unwrap(), Outcome::Accepted);
    until("the grant reaches every device", || {
        [&a, &b, &c]
            .iter()
            .all(|device| device.state().missing_epochs(2).is_empty())
    })
    .await;

    // The leader is lost. The other two elect one of themselves and remove
    // it; the removal completes without it.
    a.stop().await;
    let survivor = leader(&[&b, &c]).await;
    let removal = survivor.removal(11, &a, &[&b, &c], 2);
    assert_eq!(
        survivor.node.submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    settle(&[&b, &c], &BTreeSet::from([2, 3])).await;
    for device in [&b, &c] {
        assert_eq!(device.state().epoch, 2);
        assert_eq!(device.state().removed.get(&1), Some(&survivor.id));
    }

    // The removed device comes back: its certificate is no longer accepted,
    // so it can neither announce itself nor disturb the others.
    a.restart(VAULT).await;
    a.listen().await;
    for device in [&b, &c] {
        assert!(a.endpoint.announce(device.id, device.pin()).await.is_err());
        assert_eq!(
            device.node.directory().device_for_pin(&a.pin()),
            None::<DeviceId>
        );
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let term = b.node.raft().metrics().borrow().current_term;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(b.node.raft().metrics().borrow().current_term, term);
    assert_eq!(a.state().removed.get(&1), None);
    settle(&[&b, &c], &BTreeSet::from([2, 3])).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joining_device_installs_a_snapshot_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let a = Bare::start(&dir, 1).await;
    let b = Bare::start(&dir, 2).await;
    a.found().await;
    a.enroll(1, &b, &[&a]).await;

    // The leader keeps a snapshot and drops the log it covers, so a new
    // device cannot be sent those entries.
    let raft = a.node.raft();
    raft.trigger().snapshot().await.unwrap();
    let mut metrics = raft.metrics();
    let snapshot = loop {
        if let Some(snapshot) = metrics.borrow().snapshot {
            break snapshot;
        }
        metrics.changed().await.unwrap();
    };
    raft.trigger().purge_log(snapshot.index).await.unwrap();
    loop {
        if metrics.borrow().purged == Some(snapshot) {
            break;
        }
        metrics.changed().await.unwrap();
    }

    let c = Bare::start(&dir, 3).await;
    a.enroll(2, &c, &[&a, &b]).await;
    assert!(c.node.raft().metrics().borrow().snapshot >= Some(snapshot));
    let state = c.state();
    assert_eq!(state.members(), BTreeSet::from([1, 2, 3]));
    assert_eq!(state.epoch, 1);
    assert_eq!(state.vault_id, VAULT);
    assert_eq!(state.authors, a.state().authors);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_other_vaults_and_forged_senders_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, c) = three(&dir).await;
    let term = a.node.raft().metrics().borrow().current_term;

    // A device that was never enrolled fails the handshake, however much
    // it knows about the members.
    let stranger = Bare::start(&dir, 9).await;
    stranger
        .endpoint
        .introduce(&[a.contact(), b.contact()])
        .unwrap();
    assert!(stranger.endpoint.announce(a.id, a.pin()).await.is_err());
    assert_eq!(a.addresses.get(stranger.id), None);
    assert_eq!(a.node.directory().device_for_pin(&stranger.pin()), None);

    // A member's certificate does not open another vault's control plane,
    // and a device dials only the certificate membership records.
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let other_vault = MemberEndpoint::new([7; 32], &mut b_peers, AddressBook::default()).unwrap();
    other_vault
        .addresses()
        .observe(a.id, &a.contact().address.unwrap());
    assert!(other_vault.announce(a.id, a.pin()).await.is_err());
    assert!(matches!(
        b.endpoint.announce(a.id, c.pin()).await,
        Err(Error::PinMismatch)
    ));

    // Over its own authenticated connection, B claims to be A.
    let mut link = b.endpoint.link(c.id, &c.info());
    let ttl = Duration::from_secs(5);
    let forged_append = AppendEntriesRequest {
        vote: Vote::new_committed(99, a.id),
        prev_log_id: None,
        entries: Vec::new(),
        leader_commit: None,
    };
    assert!(matches!(
        link.call(ControlRpc::AppendEntries(forged_append), ttl)
            .await,
        Ok(ControlReply::Refused)
    ));
    let forged_vote = VoteRequest {
        vote: Vote::new(99, a.id),
        last_log_id: None,
    };
    assert!(matches!(
        link.call(ControlRpc::Vote(forged_vote), ttl).await,
        Ok(ControlReply::Refused)
    ));
    // Nor may it pass on a request another device signed.
    let borrowed = a.removal(20, &c, &[&a, &b], 2);
    assert!(matches!(
        link.call(ControlRpc::Submit(borrowed), ttl).await,
        Ok(ControlReply::Refused)
    ));
    // The same link still carries B's own requests.
    let unauthorized = stranger.request(
        21,
        ControlRequest::CancelEnrollment {
            request_id: [0; 16],
        },
    );
    assert!(matches!(
        link.call(ControlRpc::Submit(unauthorized), ttl).await,
        Ok(ControlReply::Refused)
    ));
    let own = b.request(
        22,
        ControlRequest::CancelEnrollment {
            request_id: [0; 16],
        },
    );
    match link.call(ControlRpc::Submit(own), ttl).await.unwrap() {
        ControlReply::Submit(Ok(outcome)) => {
            assert_eq!(outcome, Outcome::Rejected(Rejection::NotPending))
        }
        // C is a follower: it names the leader instead.
        ControlReply::Submit(Err(_)) => {}
        other => panic!("{other:?}"),
    }

    // Nothing above disturbed the cluster.
    assert!(a.node.raft().metrics().borrow().current_term < 99);
    assert_eq!(a.node.raft().metrics().borrow().current_term, term);
    assert_eq!(a.state().epoch, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_missed_an_enrollment_accepts_the_new_member() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, mut c) = three(&dir).await;
    c.stop().await;

    // D joins while C is away; A and B are a majority.
    let d = Bare::start(&dir, 4).await;
    a.enroll(3, &d, &[&a, &b]).await;

    // C returns knowing nothing of D: it would refuse D as leader.
    c.restart(VAULT).await;
    let directory = c.node.directory();
    assert_eq!(directory.device_for_pin(&d.pin()), None);
    assert!(!c.state().voters().contains(&d.id));

    // Announcing itself to the members it knows, C receives their roster.
    // It accepts D on their word before its own log names D.
    assert_eq!(c.endpoint.announce_all().await, 2);
    assert_eq!(directory.device_for_pin(&d.pin()), Some(d.id));
    assert_eq!(c.addresses.get(d.id), d.contact().address);
    assert!(!c.state().voters().contains(&d.id));

    // Once it listens again it catches up, whoever leads.
    c.listen().await;
    assert_eq!(c.endpoint.announce_all().await, 3);
    settle(&[&a, &b, &c, &d], &BTreeSet::from([1, 2, 3, 4])).await;
}

/// A device with a vault.
struct Member {
    host: Host,
    vault: Vault,
    invitations: InvitationStore,
}

impl Member {
    /// Creates a vault and founds its control plane.
    async fn found(dir: &TempDir) -> Self {
        let (vault, _) = Vault::create(dir.path().join("founder.db"), PASSWORD).unwrap();
        let id = device_id_from_bytes(vault.device_id().unwrap());
        let mut host = Host::start(dir, id, vault.vault_id()).await;
        control::found(&vault, &mut host.peers, &host.node)
            .await
            .unwrap();
        Self {
            host,
            vault,
            invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        }
    }

    /// Pairs a new device with this one over TLS: invitation, matching
    /// short codes, the owner's confirmation, the enrollment proposal, and
    /// the grant. `granter` is unlocked and gives the new voter the keys.
    async fn invite(&mut self, dir: &TempDir, name: &str, granter: Option<&Member>) -> Member {
        let pairing = PairingListener::bind("127.0.0.1:0", &mut self.host.peers)
            .await
            .unwrap();
        let invitation = invite(
            &self.vault,
            &mut self.invitations,
            &mut self.host.peers,
            vec![pairing.local_addr().unwrap().to_string()],
            NOW,
            300,
        )
        .unwrap();

        // The joiner runs its control-plane node from the start.
        let mut peers = PeerStore::open_in_memory().unwrap();
        let (incoming, connection) = tokio::join!(
            pairing.next_request(),
            start_pairing(invitation, &mut peers, NOW)
        );
        let connection = connection.unwrap();
        let device = connection.joiner().control_device();
        let vault_id = connection.joiner().vault_id();
        let mut host = Host::start(dir, device, vault_id).await;
        // `Host::start` made its own identity; the joiner uses the one the
        // join request named.
        host.stop().await;
        host.peers = peers;
        host.restart(vault_id).await;
        host.listen().await;

        let pending = incoming
            .unwrap()
            .review(&self.vault, &self.invitations, &mut self.host.peers, NOW)
            .unwrap();
        assert_eq!(pending.sas(), connection.sas());
        let (proposal, approved) = pending
            .approve_enrollment(
                &self.vault,
                &mut self.invitations,
                self.host.endpoint.roster(),
                self.host.endpoint.listen_port(),
                NOW,
            )
            .unwrap();
        control::submit(&self.host.node, proposal).await.unwrap();
        let (sent, received) = tokio::join!(approved.send(), connection.receive_enrollment());
        sent.unwrap();
        let (joiner, grant) = received.unwrap();

        // The grant names the members; the joiner accepts them and tells
        // them where it listens.
        let members = joiner.members(&grant).unwrap();
        host.endpoint.introduce(&members).unwrap();
        until("the joiner reaches a member", || {
            members.iter().any(|member| {
                host.addresses
                    .get(device_id_from_bytes(member.device_id))
                    .is_some()
            })
        })
        .await;
        for _ in 0..100 {
            if host.endpoint.announce_all().await == members.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        until("the joiner is a voter", || {
            self.host.state().is_settled_member(device)
        })
        .await;
        let granter = granter.unwrap_or(self);
        for request in control::grant_requests(&granter.vault, &granter.host.state()).unwrap() {
            control::submit(&granter.host.node, request).await.unwrap();
        }
        until("the joiner holds every key", || {
            joiner.enrolled(&host.state())
        })
        .await;
        let vault = joiner
            .finish_enrollment(
                &grant,
                true,
                &host.state(),
                dir.path().join(format!("{name}.db")),
                PASSWORD,
            )
            .unwrap();
        Member {
            host,
            vault,
            invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_pair_into_the_control_plane_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Member::found(&dir).await;
    let mut b = a.invite(&dir, "b", None).await;
    // B, a follower, invites the third device: its proposal is passed to
    // the leader, and the grant tells C about A, which leads.
    assert!(a.host.leads());
    let c = b.invite(&dir, "c", None).await;

    let voters: BTreeSet<DeviceId> = [&a, &b, &c].iter().map(|member| member.host.id).collect();
    until("every device applies the enrollments", || {
        [&a, &b, &c].iter().all(|member| {
            let state = member.host.state();
            state.pending.is_none()
                && state.members() == voters
                && voters
                    .iter()
                    .all(|voter| state.missing_epochs(*voter).is_empty())
        })
    })
    .await;
    assert_eq!(c.vault.vault_id(), a.vault.vault_id());
    assert_eq!(c.vault.current_epoch(), 1);
    assert_eq!(
        c.host.addresses.get(a.host.id),
        a.host.contact().address,
        "the joiner learned the leader's address from the grant"
    );

    // A removes C; A and B take the new epoch from their envelopes.
    let removal =
        control::removal_request(&a.vault, &a.host.state(), c.vault.device_id().unwrap()).unwrap();
    control::submit(&a.host.node, removal).await.unwrap();
    until("the removal completes", || {
        [&a, &b].iter().all(|member| {
            let state = member.host.state();
            state.epoch == 2 && state.pending.is_none()
        })
    })
    .await;
    let (mut a, mut b, mut c) = (a, b, c);
    for member in [&mut a, &mut b] {
        let state = member.host.state();
        let reconciled = control::reconcile(&mut member.vault, &state).unwrap();
        assert_eq!(reconciled.activated, Some(2));
        assert_eq!(reconciled.revoked, 1);
    }
    // C is cut off: nothing gives it the new key.
    let state = c.host.state();
    control::reconcile(&mut c.vault, &state).unwrap();
    assert_eq!(c.vault.current_epoch(), 1);
    assert_eq!(c.vault.epoch_keys().unwrap().len(), 1);
    assert!(c
        .host
        .endpoint
        .announce(a.host.id, a.host.pin())
        .await
        .is_err());
}
