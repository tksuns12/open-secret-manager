//! A relay the owner runs, through which a vault's devices reach each other
//! when neither can open a connection to the other: a phone on mobile data
//! and a computer at home, or two computers in two homes.
//!
//! The relay passes bytes and nothing else. Each device keeps a connection
//! to it, over TLS with the relay's certificate pinned and the device's own
//! certificate presented, and proves with the relay's token that the owner
//! gave it the relay's code. A device that wants to reach another asks for
//! it by the other's certificate pin; the relay hands each of the two a
//! one-use ticket, each opens a plain TCP connection to the relay with its
//! ticket, and the relay joins the two. The devices then run their usual
//! TLS session over it, with both certificates pinned: the relay can read
//! none of it, alter none of it unnoticed, and pass for neither device. It
//! sees which certificates ask for which, when, and how much passes.
//!
//! A device registers under the pin of the certificate it presented, which
//! it holds the key of, so no device can take another's place there. Only
//! one who holds the token can register or ask for a device: the vault's
//! devices, and a device removed from the vault until the owner makes the
//! relay a new token; a removed device reaches a member through it only to
//! be refused, as it would be directly.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use crate::{
    peers::{pin_of, TransportIdentity},
    transport::{
        client_config, handshake_error, read_frame_within, server_config, server_name,
        with_timeout, write_frame, ClientPolicy, CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT,
    },
    wire::{decode_body, encode_frame},
    Error, Result,
};

/// Version of the protocol between a device and a relay.
pub const RELAY_PROTOCOL_VERSION: u16 = 1;
const CODE_PREFIX: &str = "OSM-RELAY1-";
/// Longest relay address, as `host:port`.
const MAX_ADDRESS_LEN: usize = 128;
/// Every message between a device and the relay is a few dozen bytes.
const MAX_FRAME: usize = 256;
/// The first byte on a connection to the relay: a device's lasting
/// connection, over TLS, or a connection to be joined, with its ticket.
const CONTROL: u8 = b'C';
const JOIN: u8 = b'J';
/// A ticket not used within this long is void.
const TICKET_LIFETIME: Duration = Duration::from_secs(10);
/// A device says it is there this often; the relay ends a connection it has
/// heard nothing on for three times as long.
const PING_EVERY: Duration = Duration::from_secs(30);
const SILENT_FOR: Duration = Duration::from_secs(90);
/// After its connection to the relay ends, a device tries again this soon.
const RECONNECT_AFTER: Duration = Duration::from_secs(5);
/// Devices registered at once, connections waiting for their other half,
/// and connections open at once, on one relay.
const MAX_DEVICES: usize = 64;
const MAX_WAITING: usize = 256;
const MAX_CONNECTIONS: usize = 512;

/// What the owner gives each device to use a relay: where it is, its
/// certificate's pin, and its token. Made by the relay when it is set up
/// (`osm-relay`); kept in the vault, which carries it to every device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCode {
    version: u16,
    address: String,
    pin: [u8; 32],
    token: [u8; 32],
}

impl std::fmt::Debug for RelayCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayCode")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for RelayCode {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

impl RelayCode {
    pub fn new(address: &str, pin: [u8; 32], token: [u8; 32]) -> Result<Self> {
        let code = Self {
            version: RELAY_PROTOCOL_VERSION,
            address: address.to_owned(),
            pin,
            token,
        };
        code.check()?;
        Ok(code)
    }

    fn check(&self) -> Result<()> {
        if self.version != RELAY_PROTOCOL_VERSION
            || self.address.is_empty()
            || self.address.len() > MAX_ADDRESS_LEN
        {
            return Err(Error::InvalidRelayCode);
        }
        Ok(())
    }

    /// `OSM-RELAY1-` and the code in unpadded base64url.
    pub fn encode(&self) -> Result<Zeroizing<String>> {
        let frame = Zeroizing::new(encode_frame(self)?);
        Ok(Zeroizing::new(format!(
            "{CODE_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&frame[4..])
        )))
    }

    /// Reads a code as [`encode`](Self::encode) writes it, and only so.
    pub fn decode(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(CODE_PREFIX)
            .ok_or(Error::InvalidRelayCode)?;
        if body.len() > 512 {
            return Err(Error::InvalidRelayCode);
        }
        let bytes = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(body).map_err(|_| Error::InvalidRelayCode)?,
        );
        let code: Self = decode_body(&bytes).map_err(|_| Error::InvalidRelayCode)?;
        code.check()?;
        Ok(code)
    }

    /// Where the relay listens, as `host:port`.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The pin of the relay's certificate.
    pub fn pin(&self) -> [u8; 32] {
        self.pin
    }

    /// The relay's token, for an invitation that carries the relay.
    pub(crate) fn token(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.token)
    }
}

#[derive(Serialize, Deserialize)]
enum ToRelay {
    Register {
        version: u16,
        token: [u8; 32],
    },
    /// Join this device to the one registered under `to`.
    Dial {
        request: u32,
        to: [u8; 32],
    },
    Ping,
}

#[derive(Serialize, Deserialize)]
enum FromRelay {
    Registered,
    /// The token or the version is not the relay's.
    Refused,
    /// The ticket for the connection to `request`'s device.
    Ticket {
        request: u32,
        ticket: [u8; 32],
    },
    /// No device is registered under that pin.
    Absent {
        request: u32,
    },
    /// Another device asks for this one: the ticket for its end.
    Incoming {
        ticket: [u8; 32],
    },
    Pong,
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b)
        .fold(0u8, |difference, (x, y)| difference | (x ^ y))
        == 0
}

fn ticket() -> Result<[u8; 32]> {
    let mut ticket = [0u8; 32];
    getrandom::fill(&mut ticket).map_err(|_| Error::Transport("no randomness"))?;
    Ok(ticket)
}

/// A ticket handed out, and the ticket of the other end it is joined to.
struct Pending {
    partner: [u8; 32],
    expires: Instant,
}

#[derive(Default)]
struct Relayed {
    /// Each registered device's way to its connection, by its pin.
    devices: HashMap<[u8; 32], mpsc::Sender<FromRelay>>,
    /// Tickets not yet used.
    tickets: HashMap<[u8; 32], Pending>,
    /// Connections that came with their ticket before the other end did.
    waiting: HashMap<[u8; 32], (TcpStream, Instant)>,
}

impl Relayed {
    fn forget_expired(&mut self) {
        let now = Instant::now();
        self.tickets.retain(|_, pending| pending.expires > now);
        self.waiting.retain(|_, (_, expires)| *expires > now);
    }
}

/// Runs a relay on `listener` under `identity`, for devices that hold
/// `token`, until the task is dropped.
pub async fn serve_relay(
    listener: TcpListener,
    identity: TransportIdentity,
    token: [u8; 32],
) -> Result<()> {
    let acceptor = TlsAcceptor::from(server_config(&identity, ClientPolicy::AnyForPairing)?);
    let state = Arc::new(Mutex::new(Relayed::default()));
    let token = Arc::new(Zeroizing::new(token));
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
        let (acceptor, state, token) = (acceptor.clone(), state.clone(), token.clone());
        connections.spawn(async move {
            let _ = relay_connection(tcp, &acceptor, &state, &token).await;
        });
    }
}

async fn relay_connection(
    mut tcp: TcpStream,
    acceptor: &TlsAcceptor,
    state: &Arc<Mutex<Relayed>>,
    token: &[u8; 32],
) -> Result<()> {
    let kind = with_timeout(HANDSHAKE_TIMEOUT, tcp.read_u8()).await??;
    match kind {
        CONTROL => serve_device(tcp, acceptor, state, token).await,
        JOIN => join(tcp, state).await,
        _ => Ok(()),
    }
}

/// A device's lasting connection: its registration, its requests, and the
/// tickets for others' requests for it.
async fn serve_device(
    tcp: TcpStream,
    acceptor: &TlsAcceptor,
    state: &Arc<Mutex<Relayed>>,
    token: &[u8; 32],
) -> Result<()> {
    let mut stream = with_timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
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
    let registered = matches!(
        with_timeout(HANDSHAKE_TIMEOUT, read_frame_within(&mut stream, MAX_FRAME)).await??,
        ToRelay::Register { version, token: offered }
            if version == RELAY_PROTOCOL_VERSION && same(&offered, token)
    );
    let (sender, mut outgoing) = mpsc::channel::<FromRelay>(16);
    let accepted = registered && {
        let mut relayed = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let room = relayed.devices.len() < MAX_DEVICES || relayed.devices.contains_key(&pin);
        if room {
            // The newest connection of a device replaces an older one.
            relayed.devices.insert(pin, sender.clone());
        }
        room
    };
    if !accepted {
        write_frame(&mut stream, &FromRelay::Refused).await?;
        let _ = stream.shutdown().await;
        return Err(Error::RelayRefused);
    }
    write_frame(&mut stream, &FromRelay::Registered).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let writing = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if write_frame(&mut writer, &message).await.is_err() {
                break;
            }
        }
    });
    let outcome = async {
        loop {
            let message: ToRelay =
                with_timeout(SILENT_FOR, read_frame_within(&mut reader, MAX_FRAME)).await??;
            let reply = match message {
                ToRelay::Register { .. } => return Err(Error::ProtocolViolation),
                ToRelay::Ping => FromRelay::Pong,
                ToRelay::Dial { request, to } => {
                    let (mine, theirs) = (ticket()?, ticket()?);
                    let mut relayed = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    relayed.forget_expired();
                    let target = relayed.devices.get(&to).cloned();
                    match target {
                        Some(target) if relayed.tickets.len() + 2 <= MAX_WAITING => {
                            let expires = Instant::now() + TICKET_LIFETIME;
                            relayed.tickets.insert(
                                mine,
                                Pending {
                                    partner: theirs,
                                    expires,
                                },
                            );
                            relayed.tickets.insert(
                                theirs,
                                Pending {
                                    partner: mine,
                                    expires,
                                },
                            );
                            let _ = target.try_send(FromRelay::Incoming { ticket: theirs });
                            FromRelay::Ticket {
                                request,
                                ticket: mine,
                            }
                        }
                        _ => FromRelay::Absent { request },
                    }
                }
            };
            if sender.send(reply).await.is_err() {
                return Err(Error::ConnectionClosed);
            }
        }
    }
    .await;
    {
        let mut relayed = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if relayed
            .devices
            .get(&pin)
            .is_some_and(|current| current.same_channel(&sender))
        {
            relayed.devices.remove(&pin);
        }
    }
    drop(sender);
    writing.abort();
    outcome
}

/// A connection to be joined: its ticket, then the bytes of the session it
/// carries, passed both ways once the other end has come.
async fn join(mut tcp: TcpStream, state: &Arc<Mutex<Relayed>>) -> Result<()> {
    let mut ticket = [0u8; 32];
    with_timeout(HANDSHAKE_TIMEOUT, tcp.read_exact(&mut ticket)).await??;
    let partner = {
        let mut relayed = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        relayed.forget_expired();
        let Some(pending) = relayed.tickets.remove(&ticket) else {
            return Ok(());
        };
        match relayed.waiting.remove(&pending.partner) {
            Some((partner, _)) => partner,
            None => {
                if relayed.waiting.len() >= MAX_WAITING {
                    return Ok(());
                }
                relayed.waiting.insert(ticket, (tcp, pending.expires));
                return Ok(());
            }
        }
    };
    let mut partner = partner;
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut partner).await;
    Ok(())
}

enum Request {
    Dial {
        to: [u8; 32],
        answer: oneshot::Sender<Result<[u8; 32]>>,
    },
}

struct RelayInner {
    address: String,
    requests: mpsc::Sender<Request>,
    connected: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Drop for RelayInner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A device's use of a relay: a connection to it kept open, through which
/// it reaches other devices and they reach it.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<RelayInner>,
}

impl Relay {
    /// Starts keeping a connection to the relay `code` names, as the device
    /// with `identity`, and keeps it until the last clone is dropped. What
    /// other devices open to this one through the relay comes out of the
    /// receiver, as if from a listener, for [`crate::serve_relayed`].
    pub fn start(
        code: RelayCode,
        identity: TransportIdentity,
    ) -> (Self, mpsc::Receiver<TcpStream>) {
        let (requests, waiting) = mpsc::channel(16);
        let (incoming, accepted) = mpsc::channel(16);
        let connected = Arc::new(AtomicBool::new(false));
        let address = code.address.clone();
        let task = tokio::spawn(keep_connected(
            code,
            identity,
            waiting,
            incoming,
            connected.clone(),
        ));
        (
            Self {
                inner: Arc::new(RelayInner {
                    address,
                    requests,
                    connected,
                    task,
                }),
            },
            accepted,
        )
    }

    /// Whether this device is registered with the relay now.
    pub fn connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// Where the relay listens.
    pub fn address(&self) -> &str {
        &self.inner.address
    }

    /// A connection to the device with certificate pin `to` through the
    /// relay, on which this device then runs its TLS session as the client.
    pub async fn dial(&self, to: [u8; 32]) -> Result<TcpStream> {
        let (answer, answered) = oneshot::channel();
        self.inner
            .requests
            .send(Request::Dial { to, answer })
            .await
            .map_err(|_| Error::RelayUnavailable)?;
        let ticket = with_timeout(CONNECT_TIMEOUT, answered)
            .await?
            .map_err(|_| Error::RelayUnavailable)??;
        joining(&self.inner.address, ticket).await
    }
}

/// Opens a connection to the relay at `address` to be joined by `ticket`.
async fn joining(address: &str, ticket: [u8; 32]) -> Result<TcpStream> {
    let mut tcp = with_timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await??;
    let mut opening = [0u8; 33];
    opening[0] = JOIN;
    opening[1..].copy_from_slice(&ticket);
    tcp.write_all(&opening).await?;
    Ok(tcp)
}

async fn keep_connected(
    code: RelayCode,
    identity: TransportIdentity,
    mut requests: mpsc::Receiver<Request>,
    incoming: mpsc::Sender<TcpStream>,
    connected: Arc<AtomicBool>,
) {
    loop {
        let outcome = registered(&code, &identity, &mut requests, &incoming, &connected).await;
        connected.store(false, Ordering::SeqCst);
        // Its device let go of it.
        if outcome.is_ok() {
            return;
        }
        // Until the next attempt, a request is answered at once.
        let wait = tokio::time::sleep(RECONNECT_AFTER);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                request = requests.recv() => match request {
                    Some(Request::Dial { answer, .. }) => {
                        let _ = answer.send(Err(Error::RelayUnavailable));
                    }
                    None => return,
                },
            }
        }
    }
}

/// One connection to the relay, from registering to its end.
async fn registered(
    code: &RelayCode,
    identity: &TransportIdentity,
    requests: &mut mpsc::Receiver<Request>,
    incoming: &mpsc::Sender<TcpStream>,
    connected: &AtomicBool,
) -> Result<()> {
    let mut tcp =
        with_timeout(CONNECT_TIMEOUT, TcpStream::connect(code.address.as_str())).await??;
    tcp.write_u8(CONTROL).await?;
    let connector = TlsConnector::from(client_config(identity, code.pin)?);
    let mut stream = with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
        .await?
        .map_err(handshake_error)?;
    write_frame(
        &mut stream,
        &ToRelay::Register {
            version: RELAY_PROTOCOL_VERSION,
            token: code.token,
        },
    )
    .await?;
    match with_timeout(HANDSHAKE_TIMEOUT, read_frame_within(&mut stream, MAX_FRAME)).await?? {
        FromRelay::Registered => {}
        FromRelay::Refused => return Err(Error::RelayRefused),
        _ => return Err(Error::ProtocolViolation),
    }
    connected.store(true, Ordering::SeqCst);
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Read in a task of its own: a frame half read is not lost when a
    // request or the time to ping comes first.
    let (heard, mut messages) = mpsc::channel::<FromRelay>(16);
    let reading = tokio::spawn(async move {
        while let Ok(message) = read_frame_within(&mut reader, MAX_FRAME).await {
            if heard.send(message).await.is_err() {
                break;
            }
        }
    });
    let mut asked: HashMap<u32, oneshot::Sender<Result<[u8; 32]>>> = HashMap::new();
    let mut next = 0u32;
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_heard = Instant::now();
    let outcome = loop {
        tokio::select! {
            message = messages.recv() => {
                last_heard = Instant::now();
                match message {
                    None => break Err(Error::ConnectionClosed),
                    Some(FromRelay::Ticket { request, ticket }) => {
                        if let Some(answer) = asked.remove(&request) {
                            let _ = answer.send(Ok(ticket));
                        }
                    }
                    Some(FromRelay::Absent { request }) => {
                        if let Some(answer) = asked.remove(&request) {
                            let _ = answer.send(Err(Error::RelayAbsent));
                        }
                    }
                    Some(FromRelay::Incoming { ticket }) => {
                        let (address, incoming) = (code.address.clone(), incoming.clone());
                        tokio::spawn(async move {
                            if let Ok(tcp) = joining(&address, ticket).await {
                                let _ = incoming.send(tcp).await;
                            }
                        });
                    }
                    Some(FromRelay::Pong) => {}
                    Some(FromRelay::Registered | FromRelay::Refused) => {
                        break Err(Error::ProtocolViolation);
                    }
                }
            }
            request = requests.recv() => match request {
                None => break Ok(()),
                Some(Request::Dial { to, answer }) => {
                    let request = next;
                    next = next.wrapping_add(1);
                    if let Err(error) = write_frame(&mut writer, &ToRelay::Dial { request, to }).await {
                        let _ = answer.send(Err(Error::RelayUnavailable));
                        break Err(error);
                    }
                    asked.insert(request, answer);
                }
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENT_FOR {
                    break Err(Error::Timeout);
                }
                if let Err(error) = write_frame(&mut writer, &ToRelay::Ping).await {
                    break Err(error);
                }
            }
        }
    };
    reading.abort();
    for (_, answer) in asked {
        let _ = answer.send(Err(Error::RelayUnavailable));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_code_reads_back_only_in_its_one_form() {
        let code = RelayCode::new("relay.example:47830", [7; 32], [9; 32]).unwrap();
        let text = code.encode().unwrap();
        assert!(text.starts_with(CODE_PREFIX));
        let read = RelayCode::decode(&text).unwrap();
        assert_eq!(read, code);
        assert_eq!(read.address(), "relay.example:47830");
        assert_eq!(read.pin(), [7; 32]);
        // Spaces around it, as pasted, are no matter.
        assert_eq!(
            RelayCode::decode(&format!("  {}\n", text.as_str())).unwrap(),
            code
        );
        // Its token is never printed.
        assert!(!format!("{code:?}").contains("9, 9"));

        // Anything else is refused: another prefix, a cut or lengthened
        // body, another version, no address or too long a one.
        let body = text.strip_prefix(CODE_PREFIX).unwrap();
        for refused in [
            format!("OSM-PAIR1-{body}"),
            format!("{CODE_PREFIX}{}", &body[..body.len() - 2]),
            format!("{CODE_PREFIX}{body}AA"),
            CODE_PREFIX.to_owned(),
            String::new(),
        ] {
            assert!(RelayCode::decode(&refused).is_err(), "{refused}");
        }
        let mut other = code.clone();
        other.version = 2;
        let text = format!(
            "{CODE_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&encode_frame(&other).unwrap()[4..])
        );
        assert!(matches!(
            RelayCode::decode(&text),
            Err(Error::InvalidRelayCode)
        ));
        assert!(RelayCode::new("", [7; 32], [9; 32]).is_err());
        assert!(RelayCode::new(&"x".repeat(129), [7; 32], [9; 32]).is_err());
    }
}
