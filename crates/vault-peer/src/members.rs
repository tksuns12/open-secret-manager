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
//! certificate pin and the address the sender tries it at first, and the
//! sender itself once for each address it has now, on its home network, a
//! VPN, or IPv6. A roster is believed only when it comes from a device the
//! receiver's own state lists as a member, and then only for devices its
//! log does not name yet. This is how a device that was away while another
//! joined comes to accept that device as leader. The sender's own
//! addresses are kept ahead of what it says of others
//! ([`AddressBook::claim`]): this is how a device learns where another can
//! be reached once that one's addresses change, or a VPN gives it one more,
//! with no new invitation. Addresses are advisory: the pin authenticates.
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
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicU16, Ordering},
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    control,
    peers::{pin_of, TransportIdentity},
    transport::{
        client_config, connect_any, handshake_error, read_frame_within, read_json_frame,
        run_session, server_config, server_name, with_timeout, write_frame, write_json_frame,
        ClientPolicy, KeyLimiter, PinPolicy, SharedVault, HANDSHAKE_TIMEOUT,
        MAX_HANDSHAKE_FRAME_BYTES, NO_VAULT,
    },
    EnrollmentGrant, Error, Joiner, PeerStore, Relay, Result, SyncReport,
};

/// What a joiner's connection through the relay opens with, before its TLS:
/// the sign for the owner's open invitation, not a member.
pub(crate) const PAIRING_OPENING: u8 = b'P';

/// How long a dial waits on a device's addresses before trying the relay
/// as well.
const RELAY_AFTER: Duration = Duration::from_secs(1);

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
/// Pre-auth handshakes accepted at once, and per source IP.
const MAX_PREAUTH: usize = 32;
const MAX_PREAUTH_PER_IP: usize = 16;
/// Authenticated member connections served at once, and per device.
const MAX_CONNECTIONS: usize = 64;
const MAX_CONNECTIONS_PER_DEVICE: usize = 8;
/// Concurrent removed-device refusal notices served at once.
const MAX_REMOVED_NOTICES: usize = 4;

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

/// The roster a device sends as a connection opens, from the members of
/// its committed state with their pins: each other member once, at the
/// address it is best tried at (`best`), then this device, whose pin is
/// `own_pin`, once for each of its `own` addresses, as many as fit in
/// [`MAX_CONTACTS`] after the others. A device that names none of its own,
/// as one that does not listen, is named once without an address: what it
/// has for itself is only what others said.
pub(crate) fn opening_contacts(
    members: BTreeMap<DeviceId, [u8; 32]>,
    own_pin: [u8; 32],
    own: &[String],
    best: impl Fn(DeviceId) -> Option<String>,
) -> Vec<MemberContact> {
    let contact =
        |device: DeviceId, transport_pin: [u8; 32], address: Option<String>| MemberContact {
            device_id: device_id_to_bytes(device),
            transport_pin,
            address,
        };
    let itself = members
        .iter()
        .find(|(_, pin)| **pin == own_pin)
        .map(|(device, _)| *device);
    let mut contacts: Vec<MemberContact> = members
        .iter()
        .filter(|(_, pin)| **pin != own_pin)
        .take(MAX_CONTACTS - usize::from(itself.is_some()))
        .map(|(device, pin)| contact(*device, *pin, best(*device)))
        .collect();
    if let Some(device) = itself {
        let room = MAX_CONTACTS - contacts.len();
        if own.is_empty() {
            contacts.push(contact(device, own_pin, None));
        } else {
            for address in own.iter().take(room) {
                contacts.push(contact(device, own_pin, Some(address.clone())));
            }
        }
    }
    contacts
}

/// Most addresses kept for one device.
const ADDRESSES_PER_DEVICE: usize = 8;
/// Most addresses a device names for itself in a roster: as many as an
/// invitation names.
pub const MAX_OWN_ADDRESSES: usize = crate::MAX_INVITATION_ADDRESSES;

struct KnownAddress {
    address: String,
    /// The last connection attempt to it failed.
    failed: bool,
}

#[derive(Default)]
struct Book {
    /// Each device's addresses, best first: where it was last reached or
    /// seen from, then those it named for itself, then those other members
    /// reported, then those that failed.
    known: BTreeMap<DeviceId, Vec<KnownAddress>>,
    /// Where addresses are kept across restarts, if anywhere.
    store: Option<Connection>,
}

impl Book {
    /// Puts `address` first among `device`'s: it was just reached there,
    /// or a connection came from there.
    fn reached(&mut self, device: DeviceId, address: &str) {
        let list = self.known.entry(device).or_default();
        if list
            .first()
            .is_some_and(|first| first.address == address && !first.failed)
        {
            return;
        }
        list.retain(|known| known.address != address);
        list.insert(
            0,
            KnownAddress {
                address: address.to_owned(),
                failed: false,
            },
        );
        list.truncate(ADDRESSES_PER_DEVICE);
        self.save(device);
    }

    /// Adds `address` for `device` after those that work and before those
    /// that failed, unless it is known already. When the device has as many
    /// as are kept, an address that works is never pushed out for it.
    fn add(&mut self, device: DeviceId, address: &str) {
        let list = self.known.entry(device).or_default();
        if list.iter().any(|known| known.address == address) {
            return;
        }
        let at = list
            .iter()
            .position(|known| known.failed)
            .unwrap_or(list.len());
        list.insert(
            at,
            KnownAddress {
                address: address.to_owned(),
                failed: false,
            },
        );
        list.truncate(ADDRESSES_PER_DEVICE);
        self.save(device);
    }

    /// Puts the addresses `device` named for itself, best first, right after
    /// the one it was last reached or seen at, unless that one failed. Older
    /// ones are pushed out for them when the device has as many as are kept:
    /// a device's addresses change, as an IPv6 address that is replaced each
    /// day does, and these are the ones it has now. Nothing is written when
    /// they are in place already.
    fn claimed(&mut self, device: DeviceId, named: &[&str]) {
        let list = self.known.entry(device).or_default();
        let head = usize::from(list.first().is_some_and(|first| !first.failed));
        let named: Vec<&str> = named
            .iter()
            .copied()
            .filter(|address| head == 0 || list[0].address != *address)
            .collect();
        let in_place = list.len() >= head + named.len()
            && list[head..head + named.len()]
                .iter()
                .zip(&named)
                .all(|(known, address)| !known.failed && known.address == *address);
        if named.is_empty() || in_place {
            return;
        }
        list.retain(|known| !named.contains(&known.address.as_str()));
        for (offset, address) in named.iter().enumerate() {
            list.insert(
                head + offset,
                KnownAddress {
                    address: (*address).to_owned(),
                    failed: false,
                },
            );
        }
        list.truncate(ADDRESSES_PER_DEVICE);
        self.save(device);
    }

    /// Puts `address` behind `device`'s others: an attempt to reach it there
    /// failed.
    fn failed(&mut self, device: DeviceId, address: &str) {
        let Some(list) = self.known.get_mut(&device) else {
            return;
        };
        let Some(at) = list.iter().position(|known| known.address == address) else {
            return;
        };
        let mut known = list.remove(at);
        known.failed = true;
        list.push(known);
        self.save(device);
    }

    /// Forgets every address of `device`.
    fn forget(&mut self, device: DeviceId) {
        if self.known.remove(&device).is_none() {
            return;
        }
        if let Some(store) = &self.store {
            // As when storing one, failing to forget a hint is not an error.
            let _ = store.execute(
                "DELETE FROM device_addresses WHERE device_id = ?1",
                [device_id_to_bytes(device).as_slice()],
            );
        }
    }

    fn save(&self, device: DeviceId) {
        let (Some(store), Some(list)) = (&self.store, self.known.get(&device)) else {
            return;
        };
        // An address is a hint: failing to store one is not an error.
        let _ = (|| -> rusqlite::Result<()> {
            let transaction = store.unchecked_transaction()?;
            let id = device_id_to_bytes(device);
            transaction.execute(
                "DELETE FROM device_addresses WHERE device_id = ?1",
                [id.as_slice()],
            )?;
            for (position, known) in list.iter().enumerate() {
                transaction.execute(
                    "INSERT INTO device_addresses(device_id, position, address) VALUES (?1, ?2, ?3)",
                    params![id.as_slice(), position as i64, known.address],
                )?;
            }
            transaction.commit()
        })();
    }
}

/// Where each device can be reached: several addresses for each, best
/// first. Addresses are hints: a connection is authenticated by the
/// certificate pin, wherever it leads.
#[derive(Clone, Default)]
pub struct AddressBook {
    book: Arc<Mutex<Book>>,
}

impl AddressBook {
    /// Opens the address book kept in the SQLite file at `path`, normally
    /// the device's peer store, so addresses survive a restart.
    /// `AddressBook::default()` keeps them in memory only. A store of the
    /// second layout, which kept one address for each device, has it moved
    /// over.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Connection::open(path)?;
        store.busy_timeout(Duration::from_secs(5))?;
        osm_vault_sync::claim_store_version(&store, crate::peers::STORE_VERSION)?;
        let transaction = store.unchecked_transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS device_addresses (
                 device_id BLOB NOT NULL CHECK(length(device_id) = 16),
                 position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7),
                 address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 128),
                 PRIMARY KEY (device_id, position)
             ) STRICT;",
        )?;
        let second_layout: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'member_addresses')",
            [],
            |row| row.get(0),
        )?;
        if second_layout {
            transaction.execute_batch(
                "INSERT OR IGNORE INTO device_addresses(device_id, position, address)
                     SELECT device_id, 0, address FROM member_addresses;
                 DROP TABLE member_addresses;",
            )?;
        }
        transaction.commit()?;
        let mut known: BTreeMap<DeviceId, Vec<KnownAddress>> = BTreeMap::new();
        {
            let mut statement = store.prepare(
                "SELECT device_id, address FROM device_addresses ORDER BY device_id, position",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (device, address) in rows {
                let Ok(device) = <[u8; 16]>::try_from(device) else {
                    continue;
                };
                known
                    .entry(device_id_from_bytes(device))
                    .or_default()
                    .push(KnownAddress {
                        address,
                        failed: false,
                    });
            }
        }
        Ok(Self {
            book: Arc::new(Mutex::new(Book {
                known,
                store: Some(store),
            })),
        })
    }

    /// The address `device` is best tried at first.
    pub fn get(&self, device: DeviceId) -> Option<String> {
        let book = self.book.lock().ok()?;
        book.known
            .get(&device)
            .and_then(|list| list.first())
            .map(|known| known.address.clone())
    }

    /// Every address known for `device`, in the order to try them.
    pub fn all(&self, device: DeviceId) -> Vec<String> {
        self.book
            .lock()
            .ok()
            .and_then(|book| {
                book.known
                    .get(&device)
                    .map(|list| list.iter().map(|known| known.address.clone()).collect())
            })
            .unwrap_or_default()
    }

    /// Records an address this device saw for itself: where an
    /// authenticated connection came from, or where one was made. It is
    /// tried first.
    pub fn observe(&self, device: DeviceId, address: &str) {
        if !valid_address(address) {
            return;
        }
        if let Ok(mut book) = self.book.lock() {
            book.reached(device, address);
        }
    }

    /// Records an address another member reported, or an invitation named.
    /// It is tried after those this device reached, and pushes none out.
    pub fn suggest(&self, device: DeviceId, address: &str) {
        if !valid_address(address) {
            return;
        }
        if let Ok(mut book) = self.book.lock() {
            book.add(device, address);
        }
    }

    /// Records the addresses `device` named for itself, best first, over a
    /// connection authenticated as that device: they are tried right after
    /// where it was last reached, and push older ones out. Only an IP
    /// address with a port is taken, at most [`MAX_OWN_ADDRESSES`], so that
    /// a member cannot have names looked up.
    pub(crate) fn claim(&self, device: DeviceId, addresses: &[String]) {
        let mut named: Vec<&str> = Vec::new();
        for address in addresses {
            if valid_address(address)
                && address.parse::<SocketAddr>().is_ok()
                && !named.contains(&address.as_str())
            {
                named.push(address);
            }
        }
        named.truncate(MAX_OWN_ADDRESSES);
        if named.is_empty() {
            return;
        }
        if let Ok(mut book) = self.book.lock() {
            book.claimed(device, &named);
        }
    }

    /// Records that an attempt to reach `device` at `address` failed.
    pub(crate) fn failed(&self, device: DeviceId, address: &str) {
        if let Ok(mut book) = self.book.lock() {
            book.failed(device, address);
        }
    }

    /// Forgets every address of `device`, here and in the store.
    pub fn forget(&self, device: DeviceId) {
        if let Ok(mut book) = self.book.lock() {
            book.forget(device);
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
    /// Committed voting members that answered `OpenReply::Removed`. Removal
    /// is only accepted once `Directory::removal_confirmed` holds.
    removed_by: Mutex<BTreeSet<DeviceId>>,
    /// Concurrency cap on telling removed peers they were removed.
    removed_notices: Arc<Semaphore>,
    /// The relay this device reaches others through when their addresses do
    /// not answer, if the owner set one up.
    relay: Mutex<Option<Relay>>,
    /// Where a pairing that came through the relay goes: the listener of an
    /// open invitation. None while no invitation is open.
    pairing: Mutex<Option<mpsc::Sender<TcpStream>>>,
    /// The addresses this device names for itself, if set rather than read
    /// from its network interfaces.
    own_addresses: Mutex<Option<Vec<String>>>,
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
                removed_by: Mutex::new(BTreeSet::new()),
                removed_notices: Arc::new(Semaphore::new(MAX_REMOVED_NOTICES)),
                relay: Mutex::new(None),
                pairing: Mutex::new(None),
                own_addresses: Mutex::new(None),
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

    /// Reaches other devices through `relay` too, when their addresses do
    /// not answer; `None` stops. Connections that come through it are served
    /// by [`serve_relayed`].
    pub fn set_relay(&self, relay: Option<Relay>) {
        *self
            .inner
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = relay;
    }

    /// Passes pairings that come through the relay to `sink`, the listener
    /// of an open invitation (`PairingListener::through`).
    pub(crate) fn set_pairing_sink(&self, sink: Option<mpsc::Sender<TcpStream>>) {
        *self
            .inner
            .pairing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sink;
    }

    /// Stops passing pairings to `sink`, if it is still the one.
    pub(crate) fn clear_pairing_sink(&self, sink: &mpsc::Sender<TcpStream>) {
        let mut slot = self
            .inner
            .pairing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.as_ref().is_some_and(|held| held.same_channel(sink)) {
            *slot = None;
        }
    }

    fn pairing_sink(&self) -> Option<mpsc::Sender<TcpStream>> {
        self.inner
            .pairing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .filter(|sink| !sink.is_closed())
    }

    /// The relay this device uses, if any.
    pub fn relay(&self) -> Option<Relay> {
        self.inner
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// A connection to `device`: at the addresses known for it, best first,
    /// and through the relay as well if they have not answered within
    /// [`RELAY_AFTER`]. The address it was reached at, if not through the
    /// relay.
    async fn reach(&self, device: DeviceId, pin: [u8; 32]) -> Result<(TcpStream, Option<String>)> {
        let addresses = &self.inner.addresses;
        let candidates = addresses.all(device);
        let relay = self.relay();
        let direct = async {
            if candidates.is_empty() {
                return Err(Error::AddressUnknown);
            }
            let outcome = connect_any(&candidates).await;
            if outcome.is_err() {
                for address in &candidates {
                    addresses.failed(device, address);
                }
            }
            outcome
        };
        let Some(relay) = relay else {
            return direct.await.map(|(tcp, address)| (tcp, Some(address)));
        };
        let relayed = async {
            if !candidates.is_empty() {
                tokio::time::sleep(RELAY_AFTER).await;
            }
            relay.dial(pin).await
        };
        tokio::pin!(direct, relayed);
        // The first that answers; when one fails, the other.
        tokio::select! {
            outcome = &mut direct => match outcome {
                Ok((tcp, address)) => Ok((tcp, Some(address))),
                Err(_) => relayed.await.map(|tcp| (tcp, None)),
            },
            outcome = &mut relayed => match outcome {
                Ok(tcp) => Ok((tcp, None)),
                Err(error) => direct
                    .await
                    .map(|(tcp, address)| (tcp, Some(address)))
                    .map_err(|_| error),
            },
        }
    }

    /// Tells peers where this device accepts connections.
    pub fn set_listen_port(&self, port: u16) {
        self.inner.listen_port.store(port, Ordering::SeqCst);
    }

    pub fn listen_port(&self) -> Option<u16> {
        Some(self.inner.listen_port.load(Ordering::SeqCst)).filter(|port| *port != 0)
    }

    /// Names `addresses` as this device's own from now on, rather than those
    /// of its network interfaces: for a device that listens on one address
    /// only, and for tests. `None` goes back to the interfaces.
    pub fn set_own_addresses(&self, addresses: Option<Vec<String>>) {
        *self
            .inner
            .own_addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = addresses;
    }

    /// Where this device tells the members it talks to that it can be
    /// reached, best first: up to [`MAX_OWN_ADDRESSES`] of its addresses
    /// with the port it listens on ([`crate::local_addresses`]), read again
    /// each time, as they change from one network to the next. None while it
    /// does not listen.
    pub fn own_addresses(&self) -> Vec<String> {
        let Some(port) = self.listen_port() else {
            return Vec::new();
        };
        let set = self
            .inner
            .own_addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let mut own = set.unwrap_or_else(|| crate::local_addresses(port));
        own.retain(|address| valid_address(address));
        own.truncate(MAX_OWN_ADDRESSES);
        own
    }

    /// Forgets the addresses of the devices `state`, this device's committed
    /// control state, records as removed, which are never dialled again,
    /// and any kept for this device itself, as builds before 2026-10-13 kept
    /// what others said of it. Call it whenever the state changes; nothing
    /// is written when there is nothing to forget.
    pub fn forget_departed(&self, state: &ControlState) {
        let own = self.pin();
        let itself = state.members().into_iter().filter(|device| {
            state
                .node(*device)
                .is_some_and(|node| node.transport_pin == own)
        });
        for device in state.removed.keys().copied().chain(itself) {
            self.inner.addresses.forget(device);
        }
    }

    /// Whether a quorum of committed voting members has told this device that
    /// the vault's devices removed it (or one remaining voter after this
    /// device already applied its own pending removal). A removed device may
    /// never receive the log entry that completes its removal, so this is how
    /// it finds out without letting a single non-voter or minority peer wipe
    /// the vault.
    pub fn told_removed(&self) -> bool {
        let Ok(directory) = self.directory() else {
            return false;
        };
        let reporters = self
            .inner
            .removed_by
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        directory.removal_confirmed(&reporters)
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

    /// The roster this device sends as a connection opens: as
    /// [`roster`](Self::roster), but naming this device once for each of
    /// its own addresses ([`own_addresses`](Self::own_addresses)).
    pub(crate) fn opening_roster(&self) -> Vec<MemberContact> {
        let Ok(directory) = self.directory() else {
            return Vec::new();
        };
        opening_contacts(
            directory.members(),
            self.pin(),
            &self.own_addresses(),
            |device| self.inner.addresses.get(device),
        )
    }

    /// Accepts the devices in `contacts` on a member's word, until this
    /// device's own log names them. Only for contacts that came from a
    /// member over an authenticated channel, such as
    /// [`crate::Joiner::members`].
    pub fn introduce(&self, contacts: &[MemberContact]) -> Result<()> {
        self.take_in(contacts, None)
    }

    /// As [`introduce`](Self::introduce). With `sender`, the device the
    /// contacts came from and its pin: the addresses it names for itself are
    /// its own ([`AddressBook::claim`]), and those it names for others are
    /// hints. What a contact says of this device is not kept: it knows its
    /// own addresses; nor of a removed device.
    fn take_in(
        &self,
        contacts: &[MemberContact],
        sender: Option<(DeviceId, [u8; 32])>,
    ) -> Result<()> {
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
        let own = self.pin();
        let mut claimed = Vec::new();
        for contact in contacts {
            let Some(address) = &contact.address else {
                continue;
            };
            // Nor what a member that has not yet learned of a removal says
            // of the removed device, which is never dialled.
            if contact.transport_pin == own
                || directory
                    .removed_device_for_pin(&contact.transport_pin)
                    .is_some()
            {
                continue;
            }
            let device = device_id_from_bytes(contact.device_id);
            if sender == Some((device, contact.transport_pin)) {
                claimed.push(address.clone());
            } else {
                self.inner.addresses.suggest(device, address);
            }
        }
        if let Some((device, _)) = sender {
            self.inner.addresses.claim(device, &claimed);
        }
        Ok(())
    }

    /// Accepts the members `grant` names, as [`introduce`](Self::introduce)
    /// does, and keeps every address the invitation named for the inviter,
    /// so that this device can reach it on whichever network they share.
    pub fn introduce_grant(&self, joiner: &Joiner, grant: &EnrollmentGrant) -> Result<()> {
        self.introduce(&joiner.members(grant)?)?;
        let inviter = device_id_from_bytes(joiner.inviter_device_id());
        for address in joiner.inviter_member_addresses(grant) {
            self.inner.addresses.suggest(inviter, &address);
        }
        Ok(())
    }

    /// Takes in the roster that `from`, whose certificate has `pin`, sent,
    /// if this device's own state lists `from` as a member. Anything else is
    /// ignored: a device still being enrolled, for one, cannot vouch for
    /// others.
    fn learn(&self, from: DeviceId, pin: [u8; 32], roster: &[MemberContact]) {
        let trusted = self
            .directory()
            .is_ok_and(|directory| directory.is_member(from));
        if trusted {
            let _ = self.take_in(roster, Some((from, pin)));
        }
    }

    /// Completes the handshake and opening exchange on an incoming
    /// connection. A certificate that belongs to no accepted device fails
    /// the handshake; a removed device is told so and refused.
    pub async fn accept(&self, tcp: TcpStream) -> Result<Incoming> {
        let remote = tcp.peer_addr()?.ip().to_canonical();
        self.accept_from(tcp, Some(remote)).await
    }

    /// As [`accept`](Self::accept), for a connection that came through the
    /// relay: where it came from is the relay, not the device.
    pub async fn accept_relayed(&self, tcp: TcpStream) -> Result<Incoming> {
        self.accept_from(tcp, None).await
    }

    async fn accept_from(
        &self,
        tcp: TcpStream,
        remote: Option<std::net::IpAddr>,
    ) -> Result<Incoming> {
        let directory = self.directory()?.clone();
        // Combined deadline covering both TLS handshake and the opening frame.
        let (mut stream, device, pin, open) = with_timeout(HANDSHAKE_TIMEOUT, async {
            let mut stream = self
                .inner
                .acceptor
                .accept(tcp)
                .await
                .map_err(handshake_error)?;
            let pin = pin_of(
                stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .ok_or(Error::Handshake)?,
            );
            let Some(device) = directory.device_for_pin(&pin) else {
                if directory.removed_device_for_pin(&pin).is_none() {
                    return Err(Error::PinMismatch);
                }
                let Ok(_notice_permit) = self.inner.removed_notices.clone().try_acquire_owned()
                else {
                    return Err(Error::NotAMember);
                };
                let _: Open = read_frame_within(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
                return refuse(stream, OpenReply::Removed, Error::NotAMember)
                    .await
                    .map(|_| unreachable!());
            };
            let open: Open = read_frame_within(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
            Ok((stream, device, pin, open))
        })
        .await??;
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
        if let (Some(remote), Some(port)) = (remote, open.listen_port.filter(|port| *port != 0)) {
            self.inner
                .addresses
                .observe(device, &SocketAddr::new(remote, port).to_string());
        }
        self.learn(device, pin, &open.roster);
        with_timeout(
            OPEN_TIMEOUT,
            write_frame(
                &mut stream,
                &OpenReply::Welcome {
                    roster: self.opening_roster(),
                },
            ),
        )
        .await??;
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

    /// Dials `device` at the addresses known for it, best first, accepting
    /// only the certificate with `pin`, and completes the opening exchange.
    async fn open(
        &self,
        device: DeviceId,
        pin: [u8; 32],
        channel: Channel,
    ) -> Result<client::TlsStream<TcpStream>> {
        let addresses = &self.inner.addresses;
        let (tcp, address) = self.reach(device, pin).await?;
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
                roster: self.opening_roster(),
            },
        )
        .await?;
        match with_timeout(
            OPEN_TIMEOUT,
            read_frame_within(&mut stream, MAX_HANDSHAKE_FRAME_BYTES),
        )
        .await??
        {
            OpenReply::Welcome { roster } => {
                self.inner
                    .removed_by
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&device);
                if let Some(address) = &address {
                    addresses.observe(device, address);
                }
                self.learn(device, pin, &roster);
                Ok(stream)
            }
            OpenReply::UnsupportedVersion => Err(Error::UnsupportedVersion),
            OpenReply::VaultMismatch => Err(Error::VaultMismatch),
            OpenReply::NotAMember => Err(Error::NotAMember),
            OpenReply::Removed => {
                if self
                    .directory()
                    .is_ok_and(|directory| directory.is_voter(device))
                {
                    self.inner
                        .removed_by
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(device);
                }
                if self.told_removed() {
                    Err(Error::Removed)
                } else {
                    Err(Error::NotAMember)
                }
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
    let _ = with_timeout(OPEN_TIMEOUT, write_frame(&mut stream, &reply)).await;
    let _ = with_timeout(Duration::from_secs(2), stream.shutdown()).await;
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
/// connections it is serving. Pre-auth handshakes and authenticated member
/// sessions have separate concurrency pools so unauthenticated floods cannot
/// starve established members.
pub async fn serve_members(
    listener: TcpListener,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    sync: Option<mpsc::Sender<MemberSync>>,
) {
    let preauth = Arc::new(Semaphore::new(MAX_PREAUTH));
    let preauth_per_ip: KeyLimiter<IpAddr> = KeyLimiter::default();
    let active = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_device: KeyLimiter<DeviceId> = KeyLimiter::default();
    let mut connections = JoinSet::new();
    loop {
        let Ok((tcp, addr)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        while connections.try_join_next().is_some() {}
        let Ok(preauth_permit) = preauth.clone().try_acquire_owned() else {
            continue;
        };
        let Some(ip_guard) =
            preauth_per_ip.try_acquire(addr.ip().to_canonical(), MAX_PREAUTH_PER_IP)
        else {
            continue;
        };
        let endpoint = endpoint.clone();
        let (node, sync) = (node.clone(), sync.clone());
        let (active, per_device) = (active.clone(), per_device.clone());
        connections.spawn(async move {
            let accepted = endpoint.accept(tcp).await;
            drop(preauth_permit);
            drop(ip_guard);
            serve_authenticated(accepted, node, sync, active, per_device).await;
        });
    }
}

/// Serves the connections other devices open to this one through its relay
/// (see [`Relay::start`]), as [`serve_members`] serves those on its
/// listener, until the relay stops.
pub async fn serve_relayed(
    mut relayed: mpsc::Receiver<TcpStream>,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    sync: Option<mpsc::Sender<MemberSync>>,
) {
    let preauth = Arc::new(Semaphore::new(MAX_PREAUTH));
    let active = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_device: KeyLimiter<DeviceId> = KeyLimiter::default();
    let mut connections = JoinSet::new();
    while let Some(tcp) = relayed.recv().await {
        while connections.try_join_next().is_some() {}
        let Ok(preauth_permit) = preauth.clone().try_acquire_owned() else {
            continue;
        };
        let endpoint = endpoint.clone();
        let (node, sync) = (node.clone(), sync.clone());
        let (active, per_device) = (active.clone(), per_device.clone());
        connections.spawn(async move {
            // A joiner away from every network the invitation names opens
            // with one byte no TLS record starts with; a member goes
            // straight to TLS, whose first byte is 0x16.
            let mut tcp = tcp;
            let mut first = [0u8; 1];
            let seen = with_timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first)).await;
            match seen {
                Ok(Ok(1)) if first[0] == PAIRING_OPENING => {
                    let consumed = with_timeout(HANDSHAKE_TIMEOUT, tcp.read_exact(&mut first))
                        .await
                        .is_ok_and(|res| res.is_ok());
                    drop(preauth_permit);
                    // Taken only while an invitation is open.
                    if let (true, Some(sink)) = (consumed, endpoint.pairing_sink()) {
                        let _ = sink.try_send(tcp);
                    }
                }
                Ok(Ok(_)) => {
                    let accepted = endpoint.accept_relayed(tcp).await;
                    drop(preauth_permit);
                    serve_authenticated(accepted, node, sync, active, per_device).await;
                }
                _ => {
                    drop(preauth_permit);
                }
            }
        });
    }
}

async fn serve_authenticated(
    accepted: Result<Incoming>,
    node: Arc<ControlNode>,
    sync: Option<mpsc::Sender<MemberSync>>,
    active: Arc<Semaphore>,
    per_device: KeyLimiter<DeviceId>,
) {
    let Ok(incoming) = accepted else {
        return;
    };
    let device = match &incoming {
        Incoming::Control(connection) => connection.device(),
        Incoming::Sync(connection) => connection.device(),
    };
    let Ok(_active_permit) = active.try_acquire_owned() else {
        return;
    };
    let Some(_device_guard) = per_device.try_acquire(device, MAX_CONNECTIONS_PER_DEVICE) else {
        return;
    };
    match incoming {
        Incoming::Control(connection) => {
            let _ = connection.serve(&node).await;
        }
        Incoming::Sync(connection) => {
            if let Some(sync) = sync {
                let _ = with_timeout(OPEN_TIMEOUT, sync.send(connection)).await;
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn read_open_and_reply_removed(stream: &mut server::TlsStream<TcpStream>) {
    let _: Result<Open> = read_frame_within(stream, MAX_HANDSHAKE_FRAME_BYTES).await;
    let _ = write_frame(stream, &OpenReply::Removed).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod fixtures;
