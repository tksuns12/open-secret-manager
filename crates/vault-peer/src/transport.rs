//! TLS 1.3 over TCP with both certificates pinned.
//!
//! Each device has a self-signed transport certificate (see
//! [`TransportIdentity`]). Peers accept exactly the certificates whose
//! SHA-256 pairing or committed membership gave them; names, validity
//! periods, and system trust roots play no part. Session resumption is disabled so every connection
//! presents and checks certificates again.
//!
//! During pairing the inviter does not yet know the joiner's certificate, so
//! it accepts any client certificate and then requires that the join
//! request, signed by the joiner's device key, names that certificate.

use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use osm_vault_core::Vault;
use osm_vault_sync::InvitationStore;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Resumption,
    },
    crypto::{ring, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        NoServerSessionStorage,
    },
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use osm_vault_membership::SignedRequest;

use crate::{
    approve_enrollment,
    control::Voting,
    members::MemberContact,
    members::PAIRING_OPENING,
    pairing::{JoinReview, PendingJoiner, VerifiedCommit, PAIRING_WIRE_VERSION},
    peers::{pin_of, TransportIdentity},
    review_commit,
    wire::{decode_body, encode_frame, MAX_FRAME_BYTES},
    EnrollmentGrant, Error, Invitation, JoinChallenge, JoinCommit, JoinReveal, Joiner, PeerStore,
    Relay, RelayCode, Result, SyncMessage, SyncReport, SyncSession, MAX_INVITATION_TTL_SECS,
};

pub(crate) mod watched;

use watched::{Moved, Watched};

/// Concurrent per-key counter (e.g., per-IP or per-device connection budgets).
pub(crate) struct KeyLimiter<K: Eq + Hash + Clone> {
    counts: Arc<std::sync::Mutex<HashMap<K, usize>>>,
}

impl<K: Eq + Hash + Clone> Clone for KeyLimiter<K> {
    fn clone(&self) -> Self {
        Self {
            counts: self.counts.clone(),
        }
    }
}

impl<K: Eq + Hash + Clone> Default for KeyLimiter<K> {
    fn default() -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

pub(crate) struct KeyGuard<K: Eq + Hash + Clone> {
    counts: Arc<std::sync::Mutex<HashMap<K, usize>>>,
    key: K,
}

impl<K: Eq + Hash + Clone> Drop for KeyGuard<K> {
    fn drop(&mut self) {
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl<K: Eq + Hash + Clone> KeyLimiter<K> {
    pub(crate) fn try_acquire(&self, key: K, limit: usize) -> Option<KeyGuard<K>> {
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = map.entry(key.clone()).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        Some(KeyGuard {
            counts: self.counts.clone(),
            key,
        })
    }
}

/// Concurrent pre-auth pairing handshakes accepted at once.
const MAX_PAIRING_IN_FLIGHT: usize = 16;
/// Concurrent pre-auth pairing handshakes per client IP address.
const MAX_PAIRING_PER_IP: usize = 4;
/// Maximum online SAS challenges issued by a single pairing listener.
const MAX_PAIRING_CHALLENGES: usize = 8;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a frame outside a sync session takes to write.
pub(crate) const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
/// A sync session ends once no byte has moved either way for this long. A
/// large frame on a slow path takes as long as it takes: its bytes move.
pub(crate) const SYNC_SILENCE: Duration = Duration::from_secs(60);
/// Frames waiting between a sync session and each direction of its stream.
const SESSION_FRAMES: usize = 2;
/// How long a sync session that failed still sends what it had queued and
/// reads what arrives.
const LINGER: Duration = Duration::from_secs(2);
/// The joiner waits this long for the owner to confirm on the inviter.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(MAX_INVITATION_TTL_SECS);

#[derive(Serialize, Deserialize)]
enum PairingReply {
    Declined,
    /// The enrollment was proposed and the vault's devices accepted it.
    Enrollment(EnrollmentGrant),
    /// The owner confirmed, but the vault's devices did not accept the
    /// enrollment.
    Refused,
}

/// Accepts pairing connections. Waiting on it never touches the vault, so an
/// application can wait for a joiner, and for the owner's decision, without
/// holding the vault.
pub struct PairingListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    /// Joiners that came through the relay, while the listener takes them.
    relayed: Mutex<mpsc::Receiver<TcpStream>>,
    sink: mpsc::Sender<TcpStream>,
    /// The device whose relay they come through, once [`through`](Self::through).
    through: std::sync::Mutex<Option<crate::MemberEndpoint>>,
    /// In-flight TLS + Flight 1 handshakes, kept across `next_request` calls
    /// so rejecting one request never aborts concurrent legitimate joiners.
    in_flight: Mutex<JoinSet<Result<IncomingJoin>>>,
    /// Per-source IP cap for direct pairing handshakes.
    per_ip: KeyLimiter<IpAddr>,
    /// Number of wire v2 challenges issued on this listener (caps online SAS
    /// grinding if an invitation code leaks).
    challenges: Arc<AtomicUsize>,
    /// Optional token digest this listener is bound to: when set via
    /// [`Self::expect_token`], commits presenting any other token are refused.
    expected_token: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
}

impl Drop for PairingListener {
    fn drop(&mut self) {
        // The invitation is no longer open: nothing more is taken through
        // the relay on its account.
        let through = self
            .through
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(endpoint) = through {
            endpoint.clear_pairing_sink(&self.sink);
        }
    }
}

impl PairingListener {
    pub async fn bind(address: &str, peers: &mut PeerStore) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        Self::on(listener, peers)
    }

    /// Listens on `port` (0 for any free one), over IPv6 and IPv4 alike
    /// (see [`listen`]).
    pub fn listen(port: u16, peers: &mut PeerStore) -> Result<Self> {
        Self::on(listen(port)?, peers)
    }

    fn on(listener: TcpListener, peers: &mut PeerStore) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let (sink, relayed) = mpsc::channel(4);
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(server_config(&identity, ClientPolicy::AnyForPairing)?),
            relayed: Mutex::new(relayed),
            sink,
            through: std::sync::Mutex::new(None),
            in_flight: Mutex::new(JoinSet::new()),
            per_ip: KeyLimiter::default(),
            challenges: Arc::new(AtomicUsize::new(0)),
            expected_token: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Binds this listener to the invitation whose token has SHA-256 `digest`
    /// ([`Invitation::token_digest`]). Any commit presenting a different token
    /// is refused before a challenge is issued.
    pub fn expect_token(&self, digest: [u8; 32]) {
        *self
            .expected_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(digest);
    }

    /// Also takes the joiners that reach `endpoint`'s device through its
    /// relay, for as long as this listener lives: that is, while the
    /// invitation it was made for is open. Nothing else that comes through
    /// the relay reaches a pairing, and without a listener nothing does. One
    /// invitation is open through the relay at a time: the latest.
    pub fn through(&self, endpoint: &crate::MemberEndpoint) {
        endpoint.set_pairing_sink(Some(self.sink.clone()));
        *self
            .through
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(endpoint.clone());
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Waits for the next joiner that completes the TLS handshake and sends a
    /// wire v2 [`JoinCommit`] naming the certificate it connected with.
    /// Handshakes run concurrently up to [`MAX_PAIRING_IN_FLIGHT`] so a
    /// single stalled socket never blocks legitimate joiners.
    pub async fn next_request(&self) -> Result<IncomingJoin> {
        let mut relayed = self.relayed.lock().await;
        let mut in_flight = self.in_flight.lock().await;
        loop {
            let room = in_flight.len() < MAX_PAIRING_IN_FLIGHT;
            tokio::select! {
                accepted = self.listener.accept(), if room => {
                    let (tcp, addr) = accepted?;
                    let ip = addr.ip().to_canonical();
                    let Some(ip_guard) = self.per_ip.try_acquire(ip, MAX_PAIRING_PER_IP) else {
                        continue;
                    };
                    let acceptor = self.acceptor.clone();
                    let challenges = self.challenges.clone();
                    let expected_token = self.expected_token.clone();
                    in_flight.spawn(async move {
                        let _guard = ip_guard;
                        receive_commit(acceptor, tcp, challenges, expected_token).await
                    });
                }
                Some(tcp) = relayed.recv(), if room => {
                    let acceptor = self.acceptor.clone();
                    let challenges = self.challenges.clone();
                    let expected_token = self.expected_token.clone();
                    in_flight.spawn(async move {
                        receive_commit(acceptor, tcp, challenges, expected_token).await
                    });
                }
                Some(finished) = in_flight.join_next(), if !in_flight.is_empty() => {
                    if let Ok(Ok(incoming)) = finished {
                        return Ok(incoming);
                    }
                }
            }
        }
    }
}

async fn receive_commit(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    challenges: Arc<AtomicUsize>,
    expected_token: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
) -> Result<IncomingJoin> {
    // One combined deadline covers both TLS and Flight 1 so a slow peer
    // cannot chain two separate timeouts.
    let (stream, commit) = with_timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = acceptor.accept(tcp).await.map_err(handshake_error)?;
        let client_pin = pin_of(
            stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or(Error::Handshake)?,
        );
        let body = read_body(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
        if body.first().copied() != Some(PAIRING_WIRE_VERSION) {
            return Err(Error::UnsupportedVersion);
        }
        let commit: JoinCommit = decode_body(&body)?;
        if commit.version() != PAIRING_WIRE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if commit.joiner_transport_pin() != client_pin {
            return Err(Error::PinMismatch);
        }
        Ok((stream, commit))
    })
    .await??;
    Ok(IncomingJoin {
        stream,
        commit,
        challenges,
        expected_token,
    })
}

/// Flight 1 ([`JoinCommit`]) received over TLS, not yet reviewed against the
/// vault's invitation store.
pub struct IncomingJoin {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    commit: JoinCommit,
    challenges: Arc<AtomicUsize>,
    expected_token: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
}

impl IncomingJoin {
    /// Synchronously validates Flight 1 against the vault and invitation store
    /// (holding no lock across network I/O) and prepares Flight 2
    /// ([`JoinChallenge`]). Call [`ChallengedJoin::complete`] next to finish
    /// commit-before-reveal and derive the SAS.
    pub fn review(
        self,
        vault: &Vault,
        invitations: &InvitationStore,
        peers: &mut PeerStore,
        voting: Voting,
        relay: Option<&RelayCode>,
        now: u64,
    ) -> Result<ChallengedJoin> {
        let expected = *self
            .expected_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(expected) = expected {
            if !crate::pairing::same_bytes(&self.commit.token_digest(), &expected) {
                return Err(Error::InvalidInvitation);
            }
        }
        let (verified, challenge) =
            review_commit(vault, invitations, peers, self.commit, voting, relay, now)?;
        let mut allowed = false;
        let mut current = self.challenges.load(Ordering::SeqCst);
        while current < MAX_PAIRING_CHALLENGES {
            match self.challenges.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    allowed = true;
                    break;
                }
                Err(actual) => current = actual,
            }
        }
        if !allowed {
            return Err(Error::ProtocolViolation);
        }
        Ok(ChallengedJoin {
            stream: self.stream,
            verified,
            challenge,
        })
    }
}

/// A validated Flight 1 ready to exchange Flight 2 ([`JoinChallenge`]) and
/// Flight 3 ([`JoinReveal`]) without holding any vault lock.
pub struct ChallengedJoin {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    verified: VerifiedCommit,
    challenge: JoinChallenge,
}

impl ChallengedJoin {
    /// Sends Flight 2, receives and verifies Flight 3 within
    /// [`HANDSHAKE_TIMEOUT`], and returns the [`PendingJoin`] with the SAS
    /// ready to show to the owner.
    pub async fn complete(mut self) -> Result<PendingJoin> {
        let reveal: JoinReveal = with_timeout(HANDSHAKE_TIMEOUT, async {
            write_frame(&mut self.stream, &self.challenge).await?;
            let body = read_body(&mut self.stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
            if body.first().copied() != Some(PAIRING_WIRE_VERSION) {
                return Err(Error::UnsupportedVersion);
            }
            decode_body(&body)
        })
        .await??;
        let review = self.verified.complete(reveal)?;
        Ok(PendingJoin {
            stream: self.stream,
            review,
        })
    }
}

/// A reviewed join handshake waiting for the owner. Holds no vault borrow.
pub struct PendingJoin {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    review: JoinReview,
}

impl PendingJoin {
    /// The short code to compare with the joiner's screen.
    pub fn sas(&self) -> String {
        self.review.sas()
    }

    pub fn joiner_device_id(&self) -> [u8; 16] {
        self.review.joiner_device_id()
    }

    /// Approves the joiner after the owner confirmed, by proposing its
    /// enrollment (see [`approve_enrollment`]). Submit the returned request
    /// to the control plane, then call [`ApprovedEnrollment::send`] if it
    /// was accepted or [`ApprovedEnrollment::refuse`] if not.
    pub fn approve_enrollment(
        self,
        vault: &Vault,
        invitations: &mut InvitationStore,
        members: Vec<MemberContact>,
        voting: Voting,
        listen_port: Option<u16>,
        now: u64,
    ) -> Result<(SignedRequest, ApprovedEnrollment)> {
        let (request, grant) = approve_enrollment(
            vault,
            invitations,
            self.review,
            members,
            voting,
            listen_port,
            now,
        )?;
        Ok((
            request,
            ApprovedEnrollment {
                stream: self.stream,
                grant,
            },
        ))
    }

    pub async fn decline(mut self) -> Result<()> {
        write_frame(&mut self.stream, &PairingReply::Declined).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}

/// An enrollment the owner approved, whose proposal is on its way through
/// the control plane. The joiner is still waiting.
pub struct ApprovedEnrollment {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    grant: EnrollmentGrant,
}

impl ApprovedEnrollment {
    /// The enrollment proposal, for cancelling it if the joiner never
    /// catches up.
    pub fn request_id(&self) -> [u8; 16] {
        self.grant.request_id()
    }

    /// Sends the grant. Call once the proposal was accepted.
    pub async fn send(mut self) -> Result<()> {
        write_frame(&mut self.stream, &PairingReply::Enrollment(self.grant)).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    /// Tells the joiner that the vault's devices did not accept it.
    pub async fn refuse(mut self) -> Result<()> {
        write_frame(&mut self.stream, &PairingReply::Refused).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}

/// The joiner's open pairing connection, waiting for the owner.
pub struct PairingConnection {
    joiner: Joiner,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    /// The relay the invitation named, with the connections that reach this
    /// device through it, when the invitation named one.
    relay: Option<(Relay, mpsc::Receiver<TcpStream>)>,
}

impl PairingConnection {
    /// The short code to show while the owner confirms on the inviter.
    pub fn sas(&self) -> String {
        self.joiner.sas()
    }

    /// The relay the invitation named, which this device has been
    /// registered at since it connected, and the connections that reach it
    /// there. Until the grant names the members, the vault's devices
    /// reach this device only through it when it is away from every
    /// network they are on: use it (`MemberEndpoint::set_relay` and
    /// `serve_relayed`) before waiting for the enrollment.
    pub fn take_relay(&mut self) -> Option<(Relay, mpsc::Receiver<TcpStream>)> {
        self.relay.take()
    }

    /// This device's pending identity. Start its control-plane node under
    /// [`Joiner::control_device`] before waiting for the inviter.
    pub fn joiner(&self) -> &Joiner {
        &self.joiner
    }

    /// Waits for the inviter to report that the vault's devices accepted
    /// this device's enrollment. Introduce [`Joiner::members`] to this
    /// device's control-plane node next; the vault is created with
    /// [`Joiner::finish_enrollment`] once the enrollment completes.
    pub async fn receive_enrollment(mut self) -> Result<(Joiner, EnrollmentGrant)> {
        let reply: PairingReply = with_timeout(
            PAIRING_TIMEOUT,
            read_frame_within(&mut self.stream, MAX_HANDSHAKE_FRAME_BYTES),
        )
        .await??;
        match reply {
            PairingReply::Enrollment(grant) => Ok((self.joiner, grant)),
            PairingReply::Declined => Err(Error::NotConfirmed),
            PairingReply::Refused => Err(Error::EnrollmentRefused),
        }
    }
}

/// A join commit ready to send. Preparing it needs the peer store, and for
/// a device joining with its vault, the vault; connecting needs neither.
pub struct PreparedJoin {
    pending: PendingJoiner,
    commit: JoinCommit,
    identity: TransportIdentity,
}

impl PreparedJoin {
    /// The request of a new device, which has no vault yet.
    pub fn new(invitation: Invitation, peers: &mut PeerStore, now: u64) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let (pending, commit) = Joiner::start(invitation, identity.pin(), now)?;
        Ok(Self {
            pending,
            commit,
            identity,
        })
    }

    /// The request of a device that already holds a copy of the
    /// invitation's vault and is joining its control plane under the
    /// identity it has. The vault must be unlocked.
    pub fn with_vault(
        invitation: Invitation,
        vault: &Vault,
        peers: &mut PeerStore,
        now: u64,
    ) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let (pending, commit) = Joiner::start_with_vault(invitation, vault, identity.pin(), now)?;
        Ok(Self {
            pending,
            commit,
            identity,
        })
    }

    /// Connects to the inviter named in the invitation, pinning its
    /// certificate, and completes the 3-flight wire v2 commit-before-reveal
    /// exchange so both sides hold the same SAS.
    pub async fn connect(self) -> Result<PairingConnection> {
        let connector = TlsConnector::from(client_config(
            &self.identity,
            self.pending.inviter_transport_pin(),
        )?);
        let (mut stream, relay, direct_peer_ip) =
            reach_inviter(&self.pending, &self.identity, &connector).await?;
        let (mut joiner, reveal) = with_timeout(HANDSHAKE_TIMEOUT, async {
            write_frame(&mut stream, &self.commit).await?;
            let body = read_body(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
            if body.first().copied() != Some(PAIRING_WIRE_VERSION) {
                return Err(Error::UnsupportedVersion);
            }
            let challenge: JoinChallenge = decode_body(&body)?;
            self.pending.accept_challenge(&challenge)
        })
        .await??;
        if let Some(ip) = direct_peer_ip.filter(IpAddr::is_loopback) {
            joiner.set_connected_loopback(ip);
        }
        with_timeout(HANDSHAKE_TIMEOUT, write_frame(&mut stream, &reveal)).await??;
        Ok(PairingConnection {
            joiner,
            stream,
            relay,
        })
    }
}

/// A connection to the inviter: at the addresses its invitation names, and
/// through the relay it names, if it names one, when they have not answered
/// within a second. The relay is kept, with this device registered at it,
/// for the members that then reach it there.
async fn reach_inviter(
    joiner: &PendingJoiner,
    identity: &TransportIdentity,
    connector: &TlsConnector,
) -> Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    Option<(Relay, mpsc::Receiver<TcpStream>)>,
    Option<IpAddr>,
)> {
    // A way counts as reached when the inviter has taken the handshake, not
    // when the connection opened: one the inviter drops is not the one kept.
    let shake = |tcp: TcpStream| async move {
        with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
            .await?
            .map_err(handshake_error)
    };
    let direct = async {
        let (tcp, _) = connect_any(joiner.inviter_addresses()).await?;
        let peer_ip = tcp.peer_addr().ok().map(|addr| addr.ip().to_canonical());
        let stream = shake(tcp).await?;
        Ok::<_, Error>((stream, peer_ip))
    };
    let Some(code) = joiner.invitation_relay() else {
        let (stream, peer_ip) = direct.await?;
        return Ok((stream, None, peer_ip));
    };
    let (relay, relayed) = Relay::start(code.clone(), identity.clone());
    let dialer = relay.clone();
    let through = async {
        tokio::time::sleep(PAIRING_RELAY_AFTER).await;
        let mut tcp = dialer.dial(joiner.inviter_transport_pin()).await?;
        // The inviter tells this from a member by this byte (see
        // `serve_relayed`).
        tcp.write_all(&[PAIRING_OPENING]).await?;
        shake(tcp).await
    };
    tokio::pin!(direct, through);
    let (stream, peer_ip) = tokio::select! {
        outcome = &mut direct => match outcome {
            Ok((stream, peer_ip)) => (stream, peer_ip),
            Err(_) => (through.await?, None),
        },
        outcome = &mut through => match outcome {
            Ok(stream) => (stream, None),
            Err(_) => direct.await?,
        },
    };
    Ok((stream, Some((relay, relayed)), peer_ip))
}

/// How long the addresses an invitation names have to answer before the
/// relay is tried as well.
const PAIRING_RELAY_AFTER: Duration = Duration::from_secs(1);

/// Connects to the inviter named in `invitation`, pinning its certificate,
/// and sends the join request of a new device, which has no vault yet.
pub async fn start_pairing(
    invitation: Invitation,
    peers: &mut PeerStore,
    now: u64,
) -> Result<PairingConnection> {
    PreparedJoin::new(invitation, peers, now)?.connect().await
}

/// As [`start_pairing`], for a device joining with the vault it already
/// has; see [`PreparedJoin::with_vault`].
pub async fn start_pairing_with_vault(
    invitation: Invitation,
    vault: &Vault,
    peers: &mut PeerStore,
    now: u64,
) -> Result<PairingConnection> {
    PreparedJoin::with_vault(invitation, vault, peers, now)?
        .connect()
        .await
}

/// A vault that several tasks use, each for a moment at a time. A sync
/// session takes it once per message rather than for its whole length, so
/// two devices that dial each other at the same moment do not each wait
/// for the other with their vault held.
pub trait SharedVault: Send + Sync {
    /// Runs `f` on the vault, or returns `None` if there is none.
    fn with<R: Send>(
        &self,
        f: impl FnOnce(&mut Vault) -> R + Send,
    ) -> impl Future<Output = Option<R>> + Send;
}

impl SharedVault for Mutex<Vault> {
    async fn with<R: Send>(&self, f: impl FnOnce(&mut Vault) -> R + Send) -> Option<R> {
        Some(f(&mut *self.lock().await))
    }
}

impl SharedVault for Mutex<Option<Vault>> {
    async fn with<R: Send>(&self, f: impl FnOnce(&mut Vault) -> R + Send) -> Option<R> {
        self.lock().await.as_mut().map(f)
    }
}

impl SharedVault for Mutex<&mut Vault> {
    async fn with<R: Send>(&self, f: impl FnOnce(&mut Vault) -> R + Send) -> Option<R> {
        Some(f(&mut **self.lock().await))
    }
}

/// The vault went away while it was in use.
pub(crate) const NO_VAULT: Error = Error::Transport("the vault is no longer available");

/// Drives a [`SyncSession`] over a byte stream and returns the report and
/// the port the peer says it listens on.
///
/// A task of its own reads the peer's frames as they come, and the session
/// takes the next of them or sends its own next message, whichever can go
/// on first; it never waits to send while the peer's frames are waiting to
/// be read. Two peers that each have much to send the other thus cannot
/// leave each other's frames unread, both waiting for room to write.
pub(crate) async fn run_session<S, V>(
    stream: S,
    vault: &V,
    listen_port: Option<u16>,
) -> Result<(SyncReport, Option<u16>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    V: SharedVault + ?Sized,
{
    let moved = Moved::new();
    let (reader, writer) = tokio::io::split(Watched::new(stream, moved.clone()));
    let (outgoing, queued) = mpsc::channel::<Vec<u8>>(SESSION_FRAMES);
    let mut writer = tokio::spawn(write_frames(writer, queued));
    let (arrived, mut incoming) = mpsc::channel(SESSION_FRAMES);
    let reader = tokio::spawn(read_frames(reader, arrived));
    let result = exchange(vault, listen_port, &outgoing, &mut incoming, &moved).await;
    // Closing the queue lets the writer send what is left and shut down.
    drop(outgoing);
    let closed = if result.is_ok() {
        tokio::select! {
            written = &mut writer => written.unwrap_or(Err(Error::ConnectionClosed)),
            () = moved.stalled(SYNC_SILENCE) => Err(Error::Timeout),
        }
    } else {
        // What was queued still goes out, and what arrives is read, for a
        // moment: the peer then reads this side's `Hello`, and so learns of
        // a refusal by version, before the connection closes.
        let _ = tokio::time::timeout(LINGER, async {
            let drained = async { while incoming.recv().await.is_some() {} };
            let _ = tokio::join!(&mut writer, drained);
        })
        .await;
        Ok(())
    };
    writer.abort();
    reader.abort();
    let report = result?;
    closed?;
    Ok(report)
}

/// The session itself: sends the opening, then handles the peer's messages
/// and sends this side's, until both sides are finished and nothing is left
/// to send, or nothing moves for [`SYNC_SILENCE`].
async fn exchange<V: SharedVault + ?Sized>(
    vault: &V,
    listen_port: Option<u16>,
    outgoing: &mpsc::Sender<Vec<u8>>,
    incoming: &mut mpsc::Receiver<Result<SyncMessage>>,
    moved: &Moved,
) -> Result<(SyncReport, Option<u16>)> {
    let mut session = vault
        .with(|vault| SyncSession::start(vault, listen_port))
        .await
        .ok_or(NO_VAULT)??;
    // `Hello` and `Summary` go out before anything the peer sends is
    // handled, so that the peer learns this side's version even if this
    // side refuses the peer's.
    while session.has_outgoing() {
        let message = vault
            .with(|vault| session.next_message(vault))
            .await
            .ok_or(NO_VAULT)??;
        if let Some(message) = message {
            outgoing
                .send(encode_frame(&message)?)
                .await
                .map_err(|_| Error::ConnectionClosed)?;
        }
    }
    loop {
        if session.is_complete() && !session.has_outgoing() {
            return Ok((session.report().clone(), session.peer_listen_port()));
        }
        // The vault is held only while a message is handled or a batch is
        // read, never while waiting for the peer. The time that takes counts
        // as moving: only the peer's silence ends a session.
        tokio::select! {
            message = incoming.recv() => {
                let message = message.ok_or(Error::ConnectionClosed)??;
                vault
                    .with(|vault| session.handle(vault, message))
                    .await
                    .ok_or(NO_VAULT)??;
                moved.mark();
            }
            room = outgoing.reserve(), if session.has_outgoing() => {
                let room = room.map_err(|_| Error::ConnectionClosed)?;
                let message = vault
                    .with(|vault| session.next_message(vault))
                    .await
                    .ok_or(NO_VAULT)??;
                moved.mark();
                if let Some(message) = message {
                    room.send(encode_frame(&message)?);
                }
            }
            () = moved.stalled(SYNC_SILENCE) => return Err(Error::Timeout),
        }
    }
}

/// Reads the peer's frames in order, an error last.
async fn read_frames<R: AsyncRead + Unpin>(
    mut reader: R,
    arrived: mpsc::Sender<Result<SyncMessage>>,
) {
    loop {
        let message = read_frame(&mut reader).await;
        let failed = message.is_err();
        if arrived.send(message).await.is_err() || failed {
            return;
        }
    }
}

async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queued: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(frame) = queued.recv().await {
        writer.write_all(&frame).await.map_err(io_error)?;
    }
    let _ = writer.shutdown().await;
    Ok(())
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &impl Serialize,
) -> Result<()> {
    let frame = encode_frame(message)?;
    with_timeout(FRAME_TIMEOUT, writer.write_all(&frame))
        .await?
        .map_err(io_error)
}

/// Writes a frame whose body is JSON: control-plane RPCs use the encoding
/// the Raft log is stored in.
pub(crate) async fn write_json_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &impl Serialize,
) -> Result<()> {
    let body = serde_json::to_vec(message).map_err(|_| Error::MalformedFrame)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    with_timeout(FRAME_TIMEOUT, writer.write_all(&frame))
        .await?
        .map_err(io_error)
}

/// Reads one JSON frame. The declared length is checked before the body is
/// allocated.
pub(crate) async fn read_json_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    serde_json::from_slice(&read_body(reader, MAX_FRAME_BYTES).await?)
        .map_err(|_| Error::MalformedFrame)
}

/// Reads one frame. The declared length is checked before the body is
/// allocated.
pub(crate) async fn read_frame<R: AsyncRead + Unpin, T: Serialize + DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    read_frame_within(reader, MAX_FRAME_BYTES).await
}

/// The largest message read before a peer is known to be a member: a join
/// request, the answer to it, and the opening exchange between members.
/// Each is a few kilobytes at most.
pub(crate) const MAX_HANDSHAKE_FRAME_BYTES: usize = 64 * 1024;

/// Reads one frame of at most `limit` bytes.
pub(crate) async fn read_frame_within<R: AsyncRead + Unpin, T: Serialize + DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> Result<T> {
    decode_body(&read_body(reader, limit).await?)
}

async fn read_body<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await.map_err(io_error)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > limit {
        return Err(Error::FrameTooLarge);
    }
    // Kept as it arrives: a peer that declares a large frame and sends
    // little makes this side hold little.
    let mut body = Vec::with_capacity(length.min(MAX_HANDSHAKE_FRAME_BYTES));
    (&mut *reader)
        .take(length as u64)
        .read_to_end(&mut body)
        .await
        .map_err(io_error)?;
    if body.len() != length {
        return Err(Error::ConnectionClosed);
    }
    Ok(body)
}

/// How long a dial waits on one address before trying the next as well.
const NEXT_ADDRESS_AFTER: Duration = Duration::from_millis(300);

/// Connects to whichever of `addresses` answers first, trying them in
/// their order: each is tried a moment after the one before unless that
/// one has failed already, so that an address that never answers delays
/// the others little. Returns the stream and the address it reached.
pub(crate) async fn connect_any(addresses: &[String]) -> Result<(TcpStream, String)> {
    let mut waiting = addresses.iter();
    let mut attempts = tokio::task::JoinSet::new();
    let mut last = Error::InvalidAddress;
    loop {
        if let Some(address) = waiting.next() {
            let address = address.clone();
            attempts.spawn(async move {
                let outcome =
                    with_timeout(CONNECT_TIMEOUT, TcpStream::connect(address.as_str())).await;
                (address, outcome)
            });
        } else if attempts.is_empty() {
            return Err(last);
        }
        let outcome = if waiting.len() > 0 {
            match tokio::time::timeout(NEXT_ADDRESS_AFTER, attempts.join_next()).await {
                Ok(outcome) => outcome,
                // The time to try the next one as well.
                Err(_) => continue,
            }
        } else {
            attempts.join_next().await
        };
        match outcome {
            // The other attempts end with the set.
            Some(Ok((address, Ok(Ok(stream))))) => return Ok((stream, address)),
            Some(Ok((_, Ok(Err(error))))) => last = Error::Io(error),
            Some(Ok((_, Err(error)))) => last = error,
            Some(Err(error)) => last = Error::Io(std::io::Error::other(error)),
            None => {}
        }
    }
}

/// A listener on `port` (0 for any free one) for IPv6 and IPv4 alike, or
/// for IPv4 alone where the system has no IPv6. A connection over IPv4 then
/// comes from an IPv4 address written as IPv6 (`::ffff:a.b.c.d`), which
/// is to be turned back (`IpAddr::to_canonical`).
pub fn listen(port: u16) -> std::io::Result<TcpListener> {
    let both = || -> std::io::Result<std::net::TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(false)?;
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        socket.listen(1024)?;
        Ok(socket.into())
    };
    let listener = match both() {
        Ok(listener) => listener,
        // A port that is taken is taken: a second socket for IPv4 alone must
        // not share it (Windows lets one bind beside a dual-stack socket),
        // or two devices would answer on one port.
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => return Err(error),
        Err(_) => std::net::TcpListener::bind(("0.0.0.0", port))?,
    };
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

pub(crate) async fn with_timeout<T>(limit: Duration, future: impl Future<Output = T>) -> Result<T> {
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_| Error::Timeout)
}

fn io_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        return Error::ConnectionClosed;
    }
    handshake_error(error)
}

/// Distinguishes a certificate that failed its pin from other TLS failures.
pub(crate) fn handshake_error(error: std::io::Error) -> Error {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_)) => Error::PinMismatch,
        Some(_) => Error::Handshake,
        None => Error::Io(error),
    }
}

/// Peers never check names; this is only required by the TLS API.
pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from("osm-peer").expect("static server name is valid")
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn cert_resolver(identity: &TransportIdentity) -> Result<Arc<rustls::sign::SingleCertAndKey>> {
    let key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(identity.private_key.as_slice()),
    ))
    .map_err(|_| Error::Transport("invalid transport certificate"))?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(identity.certificate.clone())],
        key,
    ));
    Ok(Arc::new(rustls::sign::SingleCertAndKey::from(certified)))
}

/// Decides at each handshake whether a client certificate is accepted.
pub(crate) trait PinPolicy: Send + Sync + std::fmt::Debug {
    fn accepts(&self, pin: &[u8; 32]) -> bool;
}

#[derive(Debug)]
pub(crate) enum ClientPolicy {
    /// Pairing: any certificate, checked afterwards against the request.
    AnyForPairing,
    /// Control plane: whichever certificates the policy accepts when the
    /// handshake happens, so membership changes apply to new connections
    /// at once.
    Members(Arc<dyn PinPolicy>),
}

pub(crate) fn server_config(
    identity: &TransportIdentity,
    clients: ClientPolicy,
) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let resolver = cert_resolver(identity)?;
    let mut config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Transport("TLS 1.3 is unavailable"))?
        .with_client_cert_verifier(Arc::new(PinnedClients {
            policy: clients,
            provider,
        }))
        .with_cert_resolver(resolver);
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

pub(crate) fn client_config(
    identity: &TransportIdentity,
    server_pin: [u8; 32],
) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let resolver = cert_resolver(identity)?;
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Transport("TLS 1.3 is unavailable"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            pin: server_pin,
            provider,
        }))
        .with_client_cert_resolver(resolver);
    config.resumption = Resumption::disabled();
    Ok(Arc::new(config))
}

fn check_pin(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pins: &[[u8; 32]],
) -> std::result::Result<(), rustls::Error> {
    if intermediates.is_empty() && pins.contains(&pin_of(end_entity)) {
        Ok(())
    } else {
        Err(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

/// Accepts only the server certificate with the pinned hash. The handshake
/// signature is still verified, proving the peer holds that certificate's
/// key.
#[derive(Debug)]
struct PinnedServer {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        check_pin(end_entity, intermediates, &[self.pin])?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Requires a client certificate that the policy accepts.
#[derive(Debug)]
struct PinnedClients {
    policy: ClientPolicy,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let accepted = intermediates.is_empty()
            && match &self.policy {
                ClientPolicy::AnyForPairing => true,
                ClientPolicy::Members(policy) => policy.accepts(&pin_of(end_entity)),
            };
        if !accepted {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
pub(crate) fn client_config_for_tests(
    identity: &TransportIdentity,
    server_pin: [u8; 32],
) -> Arc<ClientConfig> {
    client_config(identity, server_pin).unwrap()
}

#[cfg(test)]
pub(crate) fn server_name_for_tests() -> ServerName<'static> {
    server_name()
}

#[cfg(test)]
mod fixtures;
