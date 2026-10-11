//! The control plane between devices over real TLS connections on
//! localhost. Each device has its own transport identity, listener, and
//! control-plane database; nothing is delivered in process.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use openraft::{
    raft::{AppendEntriesRequest, VoteRequest},
    Config, ServerState, Vote,
};
use osm_vault_core::{PendingDevice, Vault};
use osm_vault_membership::{
    device_id_from_bytes, ControlNode, ControlReply, ControlRequest, ControlRpc, ControlState,
    DeviceId, DeviceNode, Dialer, KeySigner, Link, MembershipChange, NodeOptions, Outcome,
    Rejection, Rotation, SignedRequest,
};
use osm_vault_sync::{
    seal_epoch_key, HpkeKeyPair, InvitationPolicy, InvitationStore, VaultId as SyncVaultId,
};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::mpsc, task::JoinHandle};

use crate::{
    control,
    control_tests::{titles, until},
    invite, serve_members, start_node, start_pairing, start_pairing_with_vault,
    tests::login,
    transport::{client_config_for_tests, server_name_for_tests},
    AddressBook, Error, MemberContact, MemberEndpoint, MemberSync, PairingListener, PeerStore,
    SyncReport, Voting,
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
    /// Sync connections the accept loop took in.
    incoming: Option<mpsc::Receiver<MemberSync>>,
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
            incoming: None,
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
        let (sync, incoming) = mpsc::channel(4);
        self.incoming = Some(incoming);
        self.server = Some(tokio::spawn(serve_members(
            listener,
            self.endpoint.clone(),
            self.node.clone(),
            Some(sync),
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
                votes: true,
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
    assert!(!a.endpoint.told_removed());
    for device in [&b, &c] {
        // It is told why, which is how it learns: the entry completing its
        // removal was never sent to it.
        assert!(matches!(
            a.endpoint.announce(device.id, device.pin()).await,
            Err(Error::Removed)
        ));
        assert_eq!(
            device.node.directory().device_for_pin(&a.pin()),
            None::<DeviceId>
        );
        // Nothing it says is taken in, such as where it now listens.
        assert_ne!(device.addresses.get(a.id), a.contact().address);
    }
    assert!(a.endpoint.told_removed());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sync_channel_is_open_to_members_only() {
    let dir = tempfile::tempdir().unwrap();
    let (a, mut b, c) = three(&dir).await;
    assert_eq!(a.endpoint.sync_peers(), vec![b.id, c.id]);
    drop(a.endpoint.connect_sync(c.id).await.unwrap());

    // A device still being enrolled may open control connections, so it
    // can catch up, but nobody syncs with it.
    let d = Bare::start(&dir, 4).await;
    assert!(matches!(
        d.endpoint.connect_sync(a.id).await,
        Err(Error::NotAMember)
    ));
    assert!(matches!(
        a.endpoint.connect_sync(d.id).await,
        Err(Error::NotAMember)
    ));

    // C's removal is proposed but cannot complete while B is away. C has
    // applied the proposal and still counts A as a member; A refuses it.
    b.stop().await;
    let removal = a.removal(30, &c, &[&a, &b], 2);
    assert_eq!(a.node.submit(removal).await.unwrap(), Outcome::Accepted);
    until("C applies the proposal", || c.state().pending.is_some()).await;
    assert!(c.node.directory().is_member(a.id));
    assert!(matches!(
        c.endpoint.connect_sync(a.id).await,
        Err(Error::NotAMember)
    ));
    assert!(matches!(
        a.endpoint.connect_sync(c.id).await,
        Err(Error::NotAMember)
    ));
    assert_eq!(a.endpoint.sync_peers(), vec![b.id]);
    // The pending change does not stop the others from syncing.
    assert!(a.node.directory().is_member(b.id));

    // B returns and the removal completes; C is then told it was removed.
    b.restart(VAULT).await;
    b.listen().await;
    b.endpoint.announce_all().await;
    settle(&[&a, &b], &BTreeSet::from([1, 2])).await;
    assert!(matches!(
        c.endpoint.connect_sync(a.id).await,
        Err(Error::Removed)
    ));
    assert!(c.endpoint.told_removed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_frame_from_a_member_ends_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let a = Bare::start(&dir, 1).await;
    let mut b = Bare::start(&dir, 2).await;
    a.found().await;
    a.enroll(1, &b, &[&a]).await;

    // B, a member, opens a connection of its own to A and declares a frame
    // far beyond the limit.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = b.peers.transport_identity().unwrap();
    let (accepted, _) = tokio::join!(
        async {
            let (tcp, _) = listener.accept().await.unwrap();
            a.endpoint.accept(tcp).await.map(|_| ())
        },
        async {
            let connector =
                tokio_rustls::TlsConnector::from(client_config_for_tests(&identity, a.pin()));
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut stream = connector
                .connect(server_name_for_tests(), tcp)
                .await
                .unwrap();
            stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    );
    assert!(matches!(accepted, Err(Error::FrameTooLarge)));
}

#[test]
fn the_address_book_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.db");
    // The peer store and the address book share one file.
    let mut peers = PeerStore::open(&path, std::sync::Arc::new(crate::NoKeystore)).unwrap();
    let pin = peers.transport_identity().unwrap().pin();
    let book = AddressBook::open(&path).unwrap();
    book.observe(1, "192.0.2.1:47820");
    book.suggest(1, "192.0.2.9:47820");
    book.suggest(2, "192.0.2.2:47820");
    book.observe(3, "");
    book.observe(4, &"x".repeat(200));
    drop(book);

    let book = AddressBook::open(&path).unwrap();
    assert_eq!(book.get(1).as_deref(), Some("192.0.2.1:47820"));
    assert_eq!(book.get(2).as_deref(), Some("192.0.2.2:47820"));
    assert_eq!(book.get(3), None);
    assert_eq!(book.get(4), None);
    assert_eq!(
        PeerStore::open(&path, std::sync::Arc::new(crate::NoKeystore))
            .unwrap()
            .transport_identity()
            .unwrap()
            .pin(),
        pin
    );
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
        Self::found_with(dir, vault).await
    }

    /// Founds the control plane of an existing vault.
    async fn found_with(dir: &TempDir, vault: Vault) -> Self {
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
        self.enroll(dir, name, granter, None, Voting::Votes).await
    }

    /// As [`Self::invite`], for a device that will not vote.
    async fn invite_without_vote(&mut self, dir: &TempDir, name: &str) -> Member {
        self.enroll(dir, name, None, None, Voting::WithoutVote)
            .await
    }

    /// As [`Self::invite`]; with `existing`, the joining device already
    /// holds that copy of the vault and joins with it instead of creating
    /// one.
    async fn enroll(
        &mut self,
        dir: &TempDir,
        name: &str,
        granter: Option<&Member>,
        existing: Option<Vault>,
        voting: Voting,
    ) -> Member {
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
        let (incoming, connection) = tokio::join!(pairing.next_request(), async {
            match &existing {
                Some(vault) => start_pairing_with_vault(invitation, vault, &mut peers, NOW).await,
                None => start_pairing(invitation, &mut peers, NOW).await,
            }
        });
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
                voting,
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
        until("the joiner is a member", || {
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
        let vault = match existing {
            Some(mut vault) => {
                assert!(joiner.has_vault());
                joiner
                    .finish_in_place(&grant, true, &host.state(), &mut vault)
                    .unwrap();
                vault
            }
            None => joiner
                .finish_enrollment(
                    &grant,
                    true,
                    &host.state(),
                    dir.path().join(format!("{name}.db")),
                    PASSWORD,
                )
                .unwrap(),
        };
        Member {
            host,
            vault,
            invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        }
    }
}

/// Syncs two members over the member endpoint: `dialer` opens the
/// connection and `server` takes it from its accept loop. Each brings its
/// vault in line with its committed state first.
async fn sync(dialer: &mut Member, server: &mut Member) -> (SyncReport, SyncReport) {
    let target = server.host.id;
    let dial = async {
        let connection = dialer.host.endpoint.connect_sync(target).await.unwrap();
        let state = dialer.host.state();
        connection.run(&mut dialer.vault, &state).await.unwrap()
    };
    let serve = async {
        let incoming = server.host.incoming.as_mut().unwrap();
        let connection = incoming.recv().await.unwrap();
        assert_eq!(connection.device(), dialer.host.id);
        let state = server.host.state();
        connection.run(&mut server.vault, &state).await.unwrap()
    };
    tokio::join!(dial, serve)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_pair_sync_and_rotate_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Member::found(&dir).await;
    a.vault.put(login("From A", "a-secret")).unwrap();
    let mut b = a.invite(&dir, "b", None).await;
    // B, a follower, invites the third device: its proposal is passed to
    // the leader, and the grant tells C about A, which leads.
    assert!(a.host.leads());
    let mut c = b.invite(&dir, "c", None).await;

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

    // Any member syncs with any other: C fetches the vault from A, which
    // did not invite it, and C's edit reaches A through B.
    let (received, sent) = sync(&mut c, &mut a).await;
    assert_eq!((received.applied, sent.sent), (1, 1));
    c.vault.put(login("From C", "c-secret")).unwrap();
    let (_, received) = sync(&mut c, &mut b).await;
    assert_eq!((received.applied, received.quarantined), (2, 0));
    let (_, received) = sync(&mut b, &mut a).await;
    assert_eq!((received.applied, received.quarantined), (1, 0));
    assert_eq!(titles(&a.vault), vec!["From A", "From C"]);

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
    let state = a.host.state();
    let reconciled = control::reconcile(&mut a.vault, &state).unwrap();
    assert_eq!(reconciled.activated, Some(2));
    assert_eq!(reconciled.revoked, 1);
    a.vault.put(login("After removal", "new secret")).unwrap();
    // Syncing brings B's vault in line with the removal before anything is
    // exchanged, so it can read what A wrote under the new epoch.
    let (_, received) = sync(&mut a, &mut b).await;
    assert!(received.applied >= 1);
    assert_eq!(b.vault.current_epoch(), 2);
    assert_eq!(b.vault.revoked_devices().unwrap().len(), 1);
    assert_eq!(titles(&b.vault), vec!["After removal", "From A", "From C"]);

    // C is cut off in both directions and is told why. Nothing gives it the
    // new key or the new revisions.
    assert!(matches!(
        c.host.endpoint.connect_sync(a.host.id).await,
        Err(Error::Removed)
    ));
    assert!(c.host.endpoint.told_removed());
    assert!(matches!(
        a.host.endpoint.connect_sync(c.host.id).await,
        Err(Error::NotAMember)
    ));
    let state = c.host.state();
    control::reconcile(&mut c.vault, &state).unwrap();
    assert_eq!(c.vault.current_epoch(), 1);
    assert_eq!(c.vault.epoch_keys().unwrap().len(), 1);
    assert_eq!(titles(&c.vault), vec!["From A", "From C"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_joins_without_a_vote_syncs_and_is_removed_by_the_one_voter_while_it_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Member::found(&dir).await;
    a.vault.put(login("From A", "a-secret")).unwrap();
    let mut phone = a.invite_without_vote(&dir, "phone").await;
    let (a_id, phone_id) = (a.host.id, phone.host.id);

    // A votes; the phone is a member without a vote, and holds the key.
    until("both devices apply the enrollment", || {
        [&a, &phone].iter().all(|member| {
            let state = member.host.state();
            state.pending.is_none()
                && state.members() == BTreeSet::from([a_id, phone_id])
                && state.voters() == BTreeSet::from([a_id])
                && state.without_vote == BTreeSet::from([phone_id])
                && state.missing_epochs(phone_id).is_empty()
        })
    })
    .await;
    assert_eq!(phone.vault.current_epoch(), 1);

    // It syncs both ways like any member.
    let (received, _) = sync(&mut phone, &mut a).await;
    assert_eq!(received.applied, 1);
    phone
        .vault
        .put(login("From the phone", "phone-secret"))
        .unwrap();
    let (_, received) = sync(&mut phone, &mut a).await;
    assert_eq!((received.applied, received.quarantined), (1, 0));
    assert_eq!(titles(&a.vault), vec!["From A", "From the phone"]);

    // The phone is lost while off. A, the one voter, is a majority alone
    // and removes it, rotating the key to itself.
    phone.host.stop().await;
    let removal =
        control::removal_request(&a.vault, &a.host.state(), phone.vault.device_id().unwrap())
            .unwrap();
    control::submit(&a.host.node, removal).await.unwrap();
    until("the removal completes", || {
        let state = a.host.state();
        state.epoch == 2 && state.pending.is_none() && state.removed.contains_key(&phone_id)
    })
    .await;
    let state = a.host.state();
    assert_eq!(state.members(), BTreeSet::from([a_id]));
    assert!(state.node(phone_id).is_none());
    let reconciled = control::reconcile(&mut a.vault, &state).unwrap();
    assert_eq!(reconciled.activated, Some(2));
    assert_eq!(reconciled.revoked, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_that_dial_each_other_at_once_both_finish() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Member::found(&dir).await;
    let mut b = a.invite(&dir, "b", None).await;
    a.vault.put(login("From A", "a-secret")).unwrap();
    b.vault.put(login("From B", "b-secret")).unwrap();

    // Each device runs an outgoing session and serves the other's incoming
    // one on the same vault. A session takes the vault per message, so
    // neither waits for the other while holding it.
    let (a_id, b_id) = (a.host.id, b.host.id);
    let (a_state, b_state) = (a.host.state(), b.host.state());
    let mut a_incoming = a.host.incoming.take().unwrap();
    let mut b_incoming = b.host.incoming.take().unwrap();
    let (a_endpoint, b_endpoint) = (a.host.endpoint.clone(), b.host.endpoint.clone());
    let a_vault = tokio::sync::Mutex::new(&mut a.vault);
    let b_vault = tokio::sync::Mutex::new(&mut b.vault);
    let all = async {
        tokio::join!(
            async {
                let connection = a_endpoint.connect_sync(b_id).await?;
                connection.run_shared(&a_vault, &a_state).await
            },
            async {
                let connection = b_endpoint.connect_sync(a_id).await?;
                connection.run_shared(&b_vault, &b_state).await
            },
            async {
                let connection = a_incoming.recv().await.unwrap();
                connection.run_shared(&a_vault, &a_state).await
            },
            async {
                let connection = b_incoming.recv().await.unwrap();
                connection.run_shared(&b_vault, &b_state).await
            },
        )
    };
    let (a_out, b_out, a_in, b_in) = tokio::time::timeout(Duration::from_secs(20), all)
        .await
        .expect("the sessions waited on each other");
    for report in [a_out, b_out, a_in, b_in] {
        report.unwrap();
    }
    assert_eq!(titles(&a.vault), vec!["From A", "From B"]);
    assert_eq!(titles(&b.vault), titles(&a.vault));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_paired_before_the_control_plane_joins_with_its_vault() {
    let dir = tempfile::tempdir().unwrap();
    // A and B were paired when the owner's confirmation alone authorized a
    // device: each has a vault and accepts the other's revisions, and
    // neither has a control plane. B has an edit A has not seen.
    let (mut a_vault, _) = Vault::create(dir.path().join("a.db"), PASSWORD).unwrap();
    let device = PendingDevice::generate();
    let material = a_vault.enrollment_material().unwrap();
    a_vault
        .authorize_device(device.device_id(), device.public_key())
        .unwrap();
    let mut b_vault = Vault::join(dir.path().join("b.db"), PASSWORD, device, material).unwrap();
    a_vault.put(login("From A", "a-secret")).unwrap();
    b_vault.put(login("Unsynced on B", "b-secret")).unwrap();
    let b_device = b_vault.device_id().unwrap();
    let b_key = b_vault.device_public_key().unwrap();

    // A founds the control plane; B is an author from the start but not a
    // voter, so it cannot be removed yet.
    let mut a = Member::found_with(&dir, a_vault).await;
    let b_id = device_id_from_bytes(b_device);
    assert_eq!(a.host.state().authors.get(&b_id), Some(&b_key));
    assert!(!a.host.state().is_enrolled(b_id));

    // An invitation for another vault is refused before anything is sent.
    let other = Member::found(&dir).await;
    let mut other_inviter = other;
    let foreign = invite(
        &other_inviter.vault,
        &mut other_inviter.invitations,
        &mut other_inviter.host.peers,
        vec!["127.0.0.1:1".to_owned()],
        NOW,
        300,
    )
    .unwrap();
    let mut scratch = PeerStore::open_in_memory().unwrap();
    assert!(matches!(
        start_pairing_with_vault(foreign, &b_vault, &mut scratch, NOW).await,
        Err(Error::VaultMismatch)
    ));

    // B joins with the vault it has: same device, same key, nothing
    // re-created, and its unsynced edit is still there.
    let mut b = a
        .enroll(&dir, "b", None, Some(b_vault), Voting::Votes)
        .await;
    assert_eq!(b.vault.device_id(), Some(b_device));
    assert_eq!(b.host.id, b_id);
    let state = a.host.state();
    assert!(state.is_active_member(b_id) && state.is_settled_member(b_id));
    assert_eq!(state.members().len(), 2);
    let (_, received) = sync(&mut b, &mut a).await;
    assert_eq!((received.applied, received.quarantined), (1, 0));
    assert_eq!(titles(&a.vault), vec!["From A", "Unsynced on B"]);
    assert_eq!(titles(&b.vault), titles(&a.vault));

    // Now a voter, B takes part in changes like any member: with two
    // voters both are needed, and it can no longer be skipped.
    let c = b.invite(&dir, "c", Some(&a)).await;
    assert!(a.host.state().members().contains(&c.host.id));
}
