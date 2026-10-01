//! Connections between a vault's devices, over TLS 1.3 with both
//! certificates pinned.
//!
//! A [`MemberEndpoint`] is one device's end of them. One listener serves
//! two channels: the control plane's RPCs (the endpoint is the [`Dialer`] a
//! [`ControlNode`] reaches other devices through) and revision sync with
//! any member. Which certificates it accepts is decided at every handshake
//! by the node's [`Directory`]: the devices its own log names, and devices
//! a member introduced. A device dials only the certificate membership
//! records for its target.
//!
//! A connection opens with an `Open` frame naming the protocol version, the
//! vault, and the channel, answered by `Welcome` or a refusal. Both carry
//! the sender's roster: the members in its committed state, each with its
//! certificate pin and last known address. A roster is believed only when
//! it comes from a device the receiver's own state lists as a member, and
//! then only for devices its log does not name yet. This is how a device
//! that was away while another joined comes to accept that device as
//! leader. Addresses are advisory: the pin authenticates.
//!
//! On the control channel each frame is then one JSON-encoded RPC and its
//! reply, in turn. The receiver checks before every RPC that the
//! certificate still belongs to an accepted device, and hands the RPC to
//! the node with that device's identity, which refuses an RPC claiming
//! another sender.
//!
//! The sync channel is open only between members: both ends require that
//! their own committed state lists the other as an enrolled member that is
//! not removed or being removed. It then carries a [`crate::SyncSession`].
//!
//! A removed device is served on neither channel. Its handshake is still
//! completed, so that it can be told it was removed.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use osm_vault_core::Vault;
use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlNode, ControlReply, ControlRpc, ControlState,
    DeviceId, DeviceNode, Dialer, Directory, Link, LinkError, NodeOptions,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    control,
    peers::{pin_of, TransportIdentity},
    transport::{
        client_config, handshake_error, read_frame, read_json_frame, run_session, server_config,
        server_name, with_timeout, write_frame, write_json_frame, ClientPolicy, PinPolicy,
        SharedVault, CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, NO_VAULT,
    },
    Error, PeerStore, Result, SyncReport,
};

/// Version of the protocol between members. Version 1 was sync between two
/// paired devices, without an opening frame.
pub const MEMBER_PROTOCOL_VERSION: u16 = 2;
/// Most members named in one roster or enrollment grant.
pub const MAX_CONTACTS: usize = 64;
const MAX_ADDRESS_LEN: usize = 128;
/// Longest wait for the opening exchange after the handshake.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A control connection with no RPC for this long is closed. A leader sends
/// heartbeats far more often.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Connections served at once, handshakes in progress included.
const MAX_CONNECTIONS: usize = 64;

/// A member of the vault as another member describes it: the certificate
/// to accept control connections from, and where it was last reached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberContact {
    pub device_id: [u8; 16],
    /// SHA-256 of the member's TLS certificate.
    pub transport_pin: [u8; 32],
    /// Advisory: the pin, not the address, authenticates the member.
    pub address: Option<String>,
}

fn valid_address(address: &str) -> bool {
    !address.is_empty() && address.len() <= MAX_ADDRESS_LEN
}

pub(crate) fn valid_contacts(contacts: &[MemberContact]) -> bool {
    contacts.len() <= MAX_CONTACTS
        && contacts
            .iter()
            .all(|contact| contact.address.as_deref().is_none_or(valid_address))
}

struct KnownAddress {
    address: String,
    /// The last connection attempt to it failed.
    failed: bool,
}

#[derive(Default)]
struct Book {
    known: BTreeMap<DeviceId, KnownAddress>,
    /// Where addresses are kept across restarts, if anywhere.
    store: Option<Connection>,
}

impl Book {
    fn record(&mut self, device: DeviceId, address: &str) {
        let unchanged = self
            .known
            .get(&device)
            .is_some_and(|known| known.address == address);
        self.known.insert(
            device,
            KnownAddress {
                address: address.to_owned(),
                failed: false,
            },
        );
        if unchanged {
            return;
        }
        if let Some(store) = &self.store {
            // An address is a hint: failing to store one is not an error.
            let _ = store.execute(
                "INSERT INTO member_addresses(device_id, address) VALUES (?1, ?2)
                 ON CONFLICT(device_id) DO UPDATE SET address = excluded.address",
                params![device_id_to_bytes(device).as_slice(), address],
            );
        }
    }
}

/// Where each device was last reached. Addresses are hints: a connection is
/// authenticated by the certificate pin, wherever it leads.
#[derive(Clone, Default)]
pub struct AddressBook {
    book: Arc<Mutex<Book>>,
}

impl AddressBook {
    /// Opens the address book kept in the SQLite file at `path`, normally
    /// the device's peer store, so addresses survive a restart.
    /// `AddressBook::default()` keeps them in memory only.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Connection::open(path)?;
        store.busy_timeout(Duration::from_secs(5))?;
        store.execute_batch(
            "CREATE TABLE IF NOT EXISTS member_addresses (
                 device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
                 address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 128)
             ) STRICT;",
        )?;
        let known = {
            let mut statement = store.prepare("SELECT device_id, address FROM member_addresses")?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.into_iter()
                .filter_map(|(device, address)| {
                    let device: [u8; 16] = device.try_into().ok()?;
                    Some((
                        device_id_from_bytes(device),
                        KnownAddress {
                            address,
                            failed: false,
                        },
                    ))
                })
                .collect()
        };
        Ok(Self {
            book: Arc::new(Mutex::new(Book {
                known,
                store: Some(store),
            })),
        })
    }

    pub fn get(&self, device: DeviceId) -> Option<String> {
        let book = self.book.lock().ok()?;
        book.known.get(&device).map(|known| known.address.clone())
    }

    /// Records an address this device saw for itself: where an
    /// authenticated connection came from, or where one was made.
    pub fn observe(&self, device: DeviceId, address: &str) {
        if !valid_address(address) {
            return;
        }
        if let Ok(mut book) = self.book.lock() {
            book.record(device, address);
        }
    }

    /// Records an address another member reported. It does not replace one
    /// this device saw for itself, unless that one stopped working.
    pub fn suggest(&self, device: DeviceId, address: &str) {
        if !valid_address(address) {
            return;
        }
        if let Ok(mut book) = self.book.lock() {
            if book.known.get(&device).is_none_or(|known| known.failed) {
                book.record(device, address);
            }
        }
    }

    fn failed(&self, device: DeviceId, address: &str) {
        if let Ok(mut book) = self.book.lock() {
            if let Some(known) = book.known.get_mut(&device) {
                known.failed |= known.address == address;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Channel {
    /// Raft RPCs and requests passed to the leader.
    Control,
    /// Revision sync between two members.
    Sync,
}

#[derive(Serialize, Deserialize)]
struct Open {
    version: u16,
    vault_id: [u8; 32],
    channel: Channel,
    /// The port this device accepts member connections on, if any. The
    /// receiver pairs it with the address the connection came from.
    listen_port: Option<u16>,
    roster: Vec<MemberContact>,
}

#[derive(Serialize, Deserialize)]
enum OpenReply {
    Welcome {
        roster: Vec<MemberContact>,
    },
    UnsupportedVersion,
    VaultMismatch,
    /// The channel is only for members, and the receiver's committed state
    /// does not list the sender as one.
    NotAMember,
    /// The vault's devices removed the sender.
    Removed,
}

/// The node's directory, once the node is running. Until then nothing is
/// accepted.
struct Trust {
    directory: OnceLock<Directory>,
}

impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trust")
            .field("bound", &self.directory.get().is_some())
            .finish()
    }
}

impl PinPolicy for Trust {
    fn accepts(&self, pin: &[u8; 32]) -> bool {
        // A removed device completes the handshake only to be told so.
        self.directory.get().is_some_and(|directory| {
            directory.device_for_pin(pin).is_some()
                || directory.removed_device_for_pin(pin).is_some()
        })
    }
}

struct Inner {
    vault_id: [u8; 32],
    identity: TransportIdentity,
    acceptor: TlsAcceptor,
    trust: Arc<Trust>,
    addresses: AddressBook,
    /// 0 until this device listens.
    listen_port: AtomicU16,
    /// A member answered that this device was removed.
    removed: AtomicBool,
}

/// This device's end of the connections between a vault's members.
#[derive(Clone)]
pub struct MemberEndpoint {
    inner: Arc<Inner>,
}

impl MemberEndpoint {
    /// An endpoint for `vault_id` under this device's transport identity.
    /// It accepts nothing until a node is started on it ([`start_node`]).
    pub fn new(vault_id: [u8; 32], peers: &mut PeerStore, addresses: AddressBook) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let trust = Arc::new(Trust {
            directory: OnceLock::new(),
        });
        let acceptor = TlsAcceptor::from(server_config(
            &identity,
            ClientPolicy::Members(trust.clone()),
        )?);
        Ok(Self {
            inner: Arc::new(Inner {
                vault_id,
                identity,
                acceptor,
                trust,
                addresses,
                listen_port: AtomicU16::new(0),
                removed: AtomicBool::new(false),
            }),
        })
    }

    /// SHA-256 of this device's TLS certificate.
    pub fn pin(&self) -> [u8; 32] {
        self.inner.identity.pin()
    }

    pub fn addresses(&self) -> &AddressBook {
        &self.inner.addresses
    }

    /// Tells peers where this device accepts connections.
    pub fn set_listen_port(&self, port: u16) {
        self.inner.listen_port.store(port, Ordering::SeqCst);
    }

    pub fn listen_port(&self) -> Option<u16> {
        Some(self.inner.listen_port.load(Ordering::SeqCst)).filter(|port| *port != 0)
    }

    /// Whether a member has told this device that the vault's devices
    /// removed it. A removed device may never receive the log entry that
    /// completes its removal, so this is how it finds out.
    pub fn told_removed(&self) -> bool {
        self.inner.removed.load(Ordering::SeqCst)
    }

    /// The other members this device may sync with: those its committed
    /// state lists as enrolled and neither removed nor being removed.
    pub fn sync_peers(&self) -> Vec<DeviceId> {
        let Ok(directory) = self.directory() else {
            return Vec::new();
        };
        let own = self.pin();
        directory
            .members()
            .into_iter()
            .filter(|(device, pin)| *pin != own && directory.is_member(*device))
            .map(|(device, _)| device)
            .collect()
    }

    fn directory(&self) -> Result<&Directory> {
        self.inner
            .trust
            .directory
            .get()
            .ok_or(Error::Transport("the control plane is not running"))
    }

    /// The vault's members in this device's committed state, itself
    /// included, each with its certificate pin and last known address.
    pub fn roster(&self) -> Vec<MemberContact> {
        let Ok(directory) = self.directory() else {
            return Vec::new();
        };
        directory
            .members()
            .into_iter()
            .take(MAX_CONTACTS)
            .map(|(device, transport_pin)| MemberContact {
                device_id: device_id_to_bytes(device),
                transport_pin,
                address: self.inner.addresses.get(device),
            })
            .collect()
    }

    /// Accepts the devices in `contacts` on a member's word, until this
    /// device's own log names them. Only for contacts that came from a
    /// member over an authenticated channel, such as
    /// [`crate::Joiner::members`].
    pub fn introduce(&self, contacts: &[MemberContact]) -> Result<()> {
        if !valid_contacts(contacts) {
            return Err(Error::ProtocolViolation);
        }
        let directory = self.directory()?;
        directory.introduce(contacts.iter().map(|contact| {
            (
                device_id_from_bytes(contact.device_id),
                contact.transport_pin,
            )
        }));
        for contact in contacts {
            if let Some(address) = &contact.address {
                self.inner
                    .addresses
                    .suggest(device_id_from_bytes(contact.device_id), address);
            }
        }
        Ok(())
    }

    /// Takes in the roster `from` sent, if this device's own state lists
    /// `from` as a member. Anything else is ignored: a device still being
    /// enrolled, for one, cannot vouch for others.
    fn learn(&self, from: DeviceId, roster: &[MemberContact]) {
        let trusted = self
            .directory()
            .is_ok_and(|directory| directory.is_member(from));
        if trusted {
            let _ = self.introduce(roster);
        }
    }

    /// Completes the handshake and opening exchange on an incoming
    /// connection. A certificate that belongs to no accepted device fails
    /// the handshake; a removed device is told so and refused.
    pub async fn accept(&self, tcp: TcpStream) -> Result<Incoming> {
        let remote = tcp.peer_addr()?.ip();
        let mut stream = with_timeout(HANDSHAKE_TIMEOUT, self.inner.acceptor.accept(tcp))
            .await?
            .map_err(handshake_error)?;
        let pin = pin_of(
            stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or(Error::Handshake)?,
        );
        let directory = self.directory()?.clone();
        let Some(device) = directory.device_for_pin(&pin) else {
            if directory.removed_device_for_pin(&pin).is_none() {
                return Err(Error::PinMismatch);
            }
            let _: Open = with_timeout(OPEN_TIMEOUT, read_frame(&mut stream)).await??;
            return refuse(stream, OpenReply::Removed, Error::NotAMember).await;
        };
        let open: Open = with_timeout(OPEN_TIMEOUT, read_frame(&mut stream)).await??;
        if open.version != MEMBER_PROTOCOL_VERSION {
            return refuse(
                stream,
                OpenReply::UnsupportedVersion,
                Error::UnsupportedVersion,
            )
            .await;
        }
        if open.vault_id != self.inner.vault_id {
            return refuse(stream, OpenReply::VaultMismatch, Error::VaultMismatch).await;
        }
        if open.channel == Channel::Sync && !directory.is_member(device) {
            return refuse(stream, OpenReply::NotAMember, Error::NotAMember).await;
        }
        if let Some(port) = open.listen_port.filter(|port| *port != 0) {
            self.inner
                .addresses
                .observe(device, &SocketAddr::new(remote, port).to_string());
        }
        self.learn(device, &open.roster);
        write_frame(
            &mut stream,
            &OpenReply::Welcome {
                roster: self.roster(),
            },
        )
        .await?;
        Ok(match open.channel {
            Channel::Control => Incoming::Control(ControlConnection {
                stream,
                device,
                pin,
                directory,
            }),
            Channel::Sync => Incoming::Sync(MemberSync {
                stream: TlsStream::Server(stream),
                device,
                listen_port: self.listen_port(),
            }),
        })
    }

    /// Opens a sync connection to `device`, which this device's committed
    /// state must list as a member that is neither removed nor being
    /// removed. Its certificate must be the one membership records.
    pub async fn connect_sync(&self, device: DeviceId) -> Result<MemberSync> {
        let directory = self.directory()?;
        if !directory.is_member(device) {
            return Err(Error::NotAMember);
        }
        let pin = *directory.members().get(&device).ok_or(Error::NotAMember)?;
        let stream = self.open(device, pin, Channel::Sync).await?;
        Ok(MemberSync {
            stream: TlsStream::Client(stream),
            device,
            listen_port: self.listen_port(),
        })
    }

    /// Dials `device` at its last known address, accepting only the
    /// certificate with `pin`, and completes the opening exchange.
    async fn open(
        &self,
        device: DeviceId,
        pin: [u8; 32],
        channel: Channel,
    ) -> Result<client::TlsStream<TcpStream>> {
        let addresses = &self.inner.addresses;
        let address = addresses.get(device).ok_or(Error::AddressUnknown)?;
        let tcp = match with_timeout(CONNECT_TIMEOUT, TcpStream::connect(address.as_str())).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(error)) => {
                addresses.failed(device, &address);
                return Err(Error::Io(error));
            }
            Err(error) => {
                addresses.failed(device, &address);
                return Err(error);
            }
        };
        let connector = TlsConnector::from(client_config(&self.inner.identity, pin)?);
        let mut stream = with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
            .await?
            .map_err(handshake_error)?;
        write_frame(
            &mut stream,
            &Open {
                version: MEMBER_PROTOCOL_VERSION,
                vault_id: self.inner.vault_id,
                channel,
                listen_port: self.listen_port(),
                roster: self.roster(),
            },
        )
        .await?;
        match with_timeout(OPEN_TIMEOUT, read_frame(&mut stream)).await?? {
            OpenReply::Welcome { roster } => {
                addresses.observe(device, &address);
                self.learn(device, &roster);
                Ok(stream)
            }
            OpenReply::UnsupportedVersion => Err(Error::UnsupportedVersion),
            OpenReply::VaultMismatch => Err(Error::VaultMismatch),
            OpenReply::NotAMember => Err(Error::NotAMember),
            OpenReply::Removed => {
                self.inner.removed.store(true, Ordering::SeqCst);
                Err(Error::Removed)
            }
        }
    }

    /// Connects to `device` only to exchange rosters and tell it where this
    /// device listens. A device being enrolled does this once it knows the
    /// members, so that whichever of them leads can reach it.
    pub async fn announce(&self, device: DeviceId, pin: [u8; 32]) -> Result<()> {
        let mut stream = self.open(device, pin, Channel::Control).await?;
        let _ = stream.shutdown().await;
        Ok(())
    }

    /// Announces this device to every accepted device with a known
    /// address, and returns how many answered.
    pub async fn announce_all(&self) -> usize {
        let Ok(directory) = self.directory() else {
            return 0;
        };
        let own = self.pin();
        let mut reached = 0;
        for (device, pin) in directory.pins() {
            if pin != own && self.announce(device, pin).await.is_ok() {
                reached += 1;
            }
        }
        reached
    }
}

impl Dialer for MemberEndpoint {
    type Link = ControlLink;

    fn link(&self, target: DeviceId, node: &DeviceNode) -> ControlLink {
        ControlLink {
            endpoint: self.clone(),
            target,
            pin: node.transport_pin,
            stream: None,
            connecting: None,
        }
    }
}

/// A control connection to one device, made when first needed and remade
/// after a failure.
pub struct ControlLink {
    endpoint: MemberEndpoint,
    target: DeviceId,
    pin: [u8; 32],
    stream: Option<client::TlsStream<TcpStream>>,
    /// Connecting runs as its own task: an RPC abandoned at its deadline
    /// then does not abandon a handshake that is nearly done.
    connecting: Option<JoinHandle<Result<client::TlsStream<TcpStream>>>>,
}

impl ControlLink {
    async fn connect(&mut self) -> std::result::Result<client::TlsStream<TcpStream>, LinkError> {
        let endpoint = self.endpoint.clone();
        let (target, pin) = (self.target, self.pin);
        let connecting = self.connecting.get_or_insert_with(|| {
            tokio::spawn(async move { endpoint.open(target, pin, Channel::Control).await })
        });
        let outcome = connecting.await;
        self.connecting = None;
        match outcome {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error @ (Error::AddressUnknown | Error::Io(_) | Error::Timeout))) => {
                Err(LinkError::Unreachable(error.to_string()))
            }
            Ok(Err(error)) => Err(LinkError::Failed(error.to_string())),
            Err(error) => Err(LinkError::Failed(error.to_string())),
        }
    }
}

impl Link for ControlLink {
    async fn call(
        &mut self,
        rpc: ControlRpc,
        ttl: Duration,
    ) -> std::result::Result<ControlReply, LinkError> {
        // The stream is taken out for the exchange and put back only after
        // a complete reply: if this call is dropped or fails midway, the
        // half-used stream goes with it.
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => self.connect().await?,
        };
        let exchange = async {
            write_json_frame(&mut stream, &rpc).await?;
            read_json_frame::<_, ControlReply>(&mut stream).await
        };
        match tokio::time::timeout(ttl, exchange).await {
            Ok(Ok(reply)) => {
                self.stream = Some(stream);
                Ok(reply)
            }
            Ok(Err(error)) => Err(LinkError::Failed(error.to_string())),
            Err(_) => Err(LinkError::Failed(
                "the device did not answer in time".into(),
            )),
        }
    }
}

impl Drop for ControlLink {
    fn drop(&mut self) {
        if let Some(connecting) = &self.connecting {
            connecting.abort();
        }
    }
}

/// An incoming control connection from an accepted device.
pub struct ControlConnection {
    stream: server::TlsStream<TcpStream>,
    device: DeviceId,
    pin: [u8; 32],
    directory: Directory,
}

impl ControlConnection {
    /// The device the certificate on this connection belongs to.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Answers the device's RPCs until it closes the connection, falls
    /// idle, or stops being an accepted device.
    pub async fn serve(mut self, node: &ControlNode) -> Result<()> {
        loop {
            let rpc: ControlRpc =
                match with_timeout(IDLE_TIMEOUT, read_json_frame(&mut self.stream)).await? {
                    Ok(rpc) => rpc,
                    Err(Error::ConnectionClosed) => return Ok(()),
                    Err(error) => return Err(error),
                };
            // Membership may have changed since the handshake: a removed
            // device loses its open connections too.
            if self.directory.device_for_pin(&self.pin) != Some(self.device) {
                return Err(Error::PinMismatch);
            }
            let reply = node.handle(self.device, rpc).await;
            write_json_frame(&mut self.stream, &reply).await?;
        }
    }
}

/// Answers an opening frame with a refusal and closes the connection.
async fn refuse(
    mut stream: server::TlsStream<TcpStream>,
    reply: OpenReply,
    error: Error,
) -> Result<Incoming> {
    write_frame(&mut stream, &reply).await?;
    let _ = stream.shutdown().await;
    Err(error)
}

/// A sync connection with a member, in either direction.
pub struct MemberSync {
    stream: TlsStream<TcpStream>,
    device: DeviceId,
    listen_port: Option<u16>,
}

impl MemberSync {
    /// The member at the other end.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Brings the vault in line with `state`, this device's committed
    /// control state, and then runs a sync session, so that revisions are
    /// judged against the current authors and removals. A locked vault
    /// only stages what it receives. Fails with `Removed`, exchanging
    /// nothing, if the state says this device was removed.
    ///
    /// The vault is taken for one message at a time, so other tasks, and
    /// other sessions, use it in between.
    pub async fn run_shared<V: SharedVault + ?Sized>(
        self,
        vault: &V,
        state: &ControlState,
    ) -> Result<SyncReport> {
        let reconciled = vault
            .with(|vault| control::reconcile(vault, state))
            .await
            .ok_or(NO_VAULT)??;
        if reconciled.removed {
            return Err(Error::Removed);
        }
        let (report, _) = run_session(self.stream, vault, self.listen_port).await?;
        Ok(report)
    }

    /// As [`Self::run_shared`], for a vault nothing else is using.
    pub async fn run(self, vault: &mut Vault, state: &ControlState) -> Result<SyncReport> {
        self.run_shared(&tokio::sync::Mutex::new(vault), state)
            .await
    }
}

/// An incoming connection after the opening exchange.
pub enum Incoming {
    Control(ControlConnection),
    Sync(MemberSync),
}

/// Starts this device's control-plane node on `endpoint`: the node reaches
/// other devices through it, and it accepts the devices the node's
/// directory lists.
pub async fn start_node(
    path: impl AsRef<Path>,
    device: DeviceId,
    endpoint: &MemberEndpoint,
    options: NodeOptions,
) -> Result<Arc<ControlNode>> {
    let node = ControlNode::start(
        path,
        device,
        endpoint.inner.vault_id,
        endpoint.clone(),
        options,
    )
    .await?;
    endpoint
        .inner
        .trust
        .directory
        .set(node.directory())
        .map_err(|_| Error::Transport("a control-plane node is already running"))?;
    Ok(Arc::new(node))
}

/// Accepts connections on `listener` until dropped, which also closes the
/// connections it is serving. Control connections are served to `node`
/// here; sync connections are handed to `sync`, whose receiver runs them
/// against the vault, and are refused if there is none. Strangers fail the
/// handshake; at most [`MAX_CONNECTIONS`] connections, handshakes included,
/// are open at once.
pub async fn serve_members(
    listener: TcpListener,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    sync: Option<mpsc::Sender<MemberSync>>,
) {
    let mut connections = JoinSet::new();
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        while connections.try_join_next().is_some() {}
        if connections.len() >= MAX_CONNECTIONS {
            continue;
        }
        let endpoint = endpoint.clone();
        let node = node.clone();
        let sync = sync.clone();
        connections.spawn(async move {
            match endpoint.accept(tcp).await {
                Ok(Incoming::Control(connection)) => {
                    let _ = connection.serve(&node).await;
                }
                Ok(Incoming::Sync(connection)) => {
                    if let Some(sync) = sync {
                        let _ = sync.send(connection).await;
                    }
                }
                Err(_) => {}
            }
        });
    }
}
