//! TLS 1.3 over TCP with both certificates pinned.
//!
//! Each device has a self-signed transport certificate (see
//! [`TransportIdentity`]). Peers accept exactly the certificate whose SHA-256
//! they were given during pairing; names, validity periods, and system trust
//! roots play no part. Session resumption is disabled so every connection
//! presents and checks certificates again.
//!
//! During pairing the inviter does not yet know the joiner's certificate, so
//! it accepts any client certificate and then requires that the join
//! request, signed by the joiner's device key, names that certificate.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use osm_vault_membership::SignedRequest;

use crate::{
    approve_enrollment, approve_join,
    members::MemberContact,
    pairing::JoinReview,
    peers::{pin_of, TransportIdentity},
    review_join,
    wire::{decode_body, encode_frame, MAX_FRAME_BYTES},
    EnrollmentGrant, Error, Invitation, JoinGrant, JoinRequest, Joiner, Peer, PeerStore, Result,
    SyncReport, SyncSession, MAX_INVITATION_TTL_SECS,
};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for one frame from a peer during sync.
pub(crate) const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
/// The joiner waits this long for the owner to confirm on the inviter.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(MAX_INVITATION_TTL_SECS);
const OUTGOING_FRAMES: usize = 16;

#[derive(Serialize, Deserialize)]
enum PairingReply {
    Grant(JoinGrant),
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
}

impl PairingListener {
    pub async fn bind(address: &str, peers: &mut PeerStore) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let identity = peers.transport_identity()?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(server_config(&identity, ClientPolicy::AnyForPairing)?),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Waits for the next joiner that completes the handshake and sends a
    /// request naming the certificate it connected with. Anything else (junk,
    /// failed handshakes, mismatched certificates) is dropped and the wait
    /// continues.
    pub async fn next_request(&self) -> Result<IncomingJoin> {
        loop {
            let (tcp, _) = self.listener.accept().await?;
            if let Ok(incoming) = self.receive(tcp).await {
                return Ok(incoming);
            }
        }
    }

    async fn receive(&self, tcp: TcpStream) -> Result<IncomingJoin> {
        let mut stream = with_timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
            .await?
            .map_err(handshake_error)?;
        let client_pin = pin_of(
            stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or(Error::Handshake)?,
        );
        let request: JoinRequest = with_timeout(FRAME_TIMEOUT, read_frame(&mut stream)).await??;
        // The request is signed by the joiner's device key; the certificate
        // on this connection must be the one it names.
        if request.joiner_transport_pin() != client_pin {
            return Err(Error::PinMismatch);
        }
        Ok(IncomingJoin { stream, request })
    }
}

/// A join request received over TLS, not yet reviewed.
pub struct IncomingJoin {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    request: JoinRequest,
}

impl IncomingJoin {
    /// Validates the request with [`review_join`]. Only a request that passes
    /// should be shown to the owner.
    pub fn review(
        self,
        vault: &Vault,
        invitations: &InvitationStore,
        peers: &mut PeerStore,
        now: u64,
    ) -> Result<PendingJoin> {
        let review = review_join(vault, invitations, peers, self.request, now)?;
        Ok(PendingJoin {
            stream: self.stream,
            review,
        })
    }
}

/// A reviewed join request waiting for the owner. Holds no vault borrow.
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

    /// Completes pairing on this device after the owner confirmed. Call
    /// [`ApprovedJoin::send`] afterwards; it needs no vault. `sync_port`
    /// tells the joiner where this device accepts sync connections.
    pub fn approve(
        self,
        vault: &mut Vault,
        invitations: &mut InvitationStore,
        peers: &mut PeerStore,
        sync_port: Option<u16>,
        now: u64,
    ) -> Result<ApprovedJoin> {
        let grant = approve_join(vault, invitations, peers, self.review, sync_port, now)?;
        Ok(ApprovedJoin {
            stream: self.stream,
            grant,
        })
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
        listen_port: Option<u16>,
        now: u64,
    ) -> Result<(SignedRequest, ApprovedEnrollment)> {
        let (request, grant) =
            approve_enrollment(vault, invitations, self.review, members, listen_port, now)?;
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

/// An approved pairing whose grant still has to reach the joiner.
pub struct ApprovedJoin {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    grant: JoinGrant,
}

impl ApprovedJoin {
    pub async fn send(mut self) -> Result<()> {
        write_frame(&mut self.stream, &PairingReply::Grant(self.grant)).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}

/// Waits for a joiner, asks the owner to confirm the short code with
/// `confirm`, and sends the grant. Requests that fail review are dropped and
/// the wait continues until the invitation window closes. Returns
/// `NotConfirmed` if the owner declines.
pub async fn accept_pairing<C, F>(
    listener: &PairingListener,
    vault: &mut Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    mut confirm: C,
    clock: impl Fn() -> u64,
) -> Result<()>
where
    C: FnMut(String) -> F,
    F: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + PAIRING_TIMEOUT;
    loop {
        let incoming = tokio::time::timeout_at(deadline, listener.next_request())
            .await
            .map_err(|_| Error::Timeout)??;
        let Ok(pending) = incoming.review(vault, invitations, peers, clock()) else {
            continue;
        };
        if !confirm(pending.sas()).await {
            pending.decline().await?;
            return Err(Error::NotConfirmed);
        }
        return pending
            .approve(vault, invitations, peers, None, clock())?
            .send()
            .await;
    }
}

/// The joiner's open pairing connection, waiting for the owner.
pub struct PairingConnection {
    joiner: Joiner,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

impl PairingConnection {
    /// The short code to show while the owner confirms on the inviter.
    pub fn sas(&self) -> String {
        self.joiner.sas()
    }

    /// Waits for the inviter's decision. Confirm the short code on this
    /// device too before calling [`Joiner::finish`] with the grant.
    pub async fn receive_grant(mut self) -> Result<(Joiner, JoinGrant)> {
        let reply: PairingReply =
            with_timeout(PAIRING_TIMEOUT, read_frame(&mut self.stream)).await??;
        match reply {
            PairingReply::Grant(grant) => Ok((self.joiner, grant)),
            PairingReply::Declined => Err(Error::NotConfirmed),
            PairingReply::Refused => Err(Error::EnrollmentRefused),
            PairingReply::Enrollment(_) => Err(Error::ProtocolViolation),
        }
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
        let reply: PairingReply =
            with_timeout(PAIRING_TIMEOUT, read_frame(&mut self.stream)).await??;
        match reply {
            PairingReply::Enrollment(grant) => Ok((self.joiner, grant)),
            PairingReply::Declined => Err(Error::NotConfirmed),
            PairingReply::Refused => Err(Error::EnrollmentRefused),
            PairingReply::Grant(_) => Err(Error::ProtocolViolation),
        }
    }
}

/// Connects to the inviter named in `invitation`, pinning its certificate,
/// and sends the join request.
pub async fn start_pairing(
    invitation: Invitation,
    peers: &mut PeerStore,
    now: u64,
) -> Result<PairingConnection> {
    let identity = peers.transport_identity()?;
    let server_pin = invitation.inviter_transport_pin();
    let addresses = invitation.addresses().to_vec();
    let (joiner, request) = Joiner::start(invitation, identity.pin(), now)?;
    let connector = TlsConnector::from(client_config(&identity, server_pin)?);
    let tcp = connect_first(&addresses).await?;
    let mut stream = with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
        .await?
        .map_err(handshake_error)?;
    write_frame(&mut stream, &request).await?;
    Ok(PairingConnection { joiner, stream })
}

/// Pinned TLS settings for syncing with the paired device. Handshakes made
/// through it never touch the vault.
pub struct SyncEndpoint {
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    peer: Peer,
}

impl SyncEndpoint {
    pub fn load(peers: &mut PeerStore) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let peer = peers.peers()?.into_iter().next().ok_or(Error::NotPaired)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(server_config(
                &identity,
                ClientPolicy::Pinned(vec![peer.transport_pin]),
            )?),
            connector: TlsConnector::from(client_config(&identity, peer.transport_pin)?),
            peer,
        })
    }

    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Handshakes with an incoming connection, refusing any certificate but
    /// the paired device's.
    pub async fn accept(&self, tcp: TcpStream) -> Result<SyncConnection> {
        let remote = tcp.peer_addr()?.ip();
        let stream = with_timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
            .await?
            .map_err(handshake_error)?;
        Ok(SyncConnection {
            stream: tokio_rustls::TlsStream::Server(stream),
            remote,
        })
    }

    /// Dials the paired device, refusing any certificate but its own.
    pub async fn connect(&self, address: &str) -> Result<SyncConnection> {
        let tcp = connect_first(&[address.to_owned()]).await?;
        let remote = tcp.peer_addr()?.ip();
        let stream = with_timeout(
            HANDSHAKE_TIMEOUT,
            self.connector.connect(server_name(), tcp),
        )
        .await?
        .map_err(handshake_error)?;
        Ok(SyncConnection {
            stream: tokio_rustls::TlsStream::Client(stream),
            remote,
        })
    }
}

/// An authenticated connection to the paired device, ready for a session.
pub struct SyncConnection {
    stream: tokio_rustls::TlsStream<TcpStream>,
    remote: IpAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncOutcome {
    pub report: SyncReport,
    /// Where the peer can be reached: the address it connected from, with
    /// the port it says it listens on. `None` if it does not listen.
    pub peer_address: Option<String>,
}

impl SyncConnection {
    /// Runs a session. `listen_port` tells the peer where this device can be
    /// reached, if it listens.
    pub async fn run(self, vault: &mut Vault, listen_port: Option<u16>) -> Result<SyncOutcome> {
        let remote = self.remote;
        let (report, peer_port) = run_session(self.stream, vault, listen_port).await?;
        Ok(SyncOutcome {
            report,
            peer_address: peer_port.map(|port| SocketAddr::new(remote, port).to_string()),
        })
    }
}

/// Accepts one connection from the paired device and runs a sync session,
/// then records where the peer listens. A client presenting any other
/// certificate is refused during the handshake.
pub async fn serve_sync(
    listener: &TcpListener,
    vault: &mut Vault,
    peers: &mut PeerStore,
) -> Result<SyncReport> {
    let endpoint = SyncEndpoint::load(peers)?;
    let (tcp, _) = listener.accept().await?;
    let connection = endpoint.accept(tcp).await?;
    let outcome = connection
        .run(vault, Some(listener.local_addr()?.port()))
        .await?;
    if let Some(address) = &outcome.peer_address {
        peers.set_address(&endpoint.peer().device_id, address)?;
    }
    Ok(outcome.report)
}

/// Connects to the paired device at `address`, pinning its certificate, and
/// runs a sync session.
pub async fn connect_sync(
    address: &str,
    vault: &mut Vault,
    peers: &mut PeerStore,
) -> Result<SyncReport> {
    let endpoint = SyncEndpoint::load(peers)?;
    let connection = endpoint.connect(address).await?;
    Ok(connection.run(vault, None).await?.report)
}

/// Drives a [`SyncSession`] over a byte stream and returns the report and
/// the port the peer says it listens on. Reading and writing run
/// concurrently, so two peers sending large batches at once cannot block
/// each other on full socket buffers.
pub(crate) async fn run_session<S>(
    stream: S,
    vault: &mut Vault,
    listen_port: Option<u16>,
) -> Result<(SyncReport, Option<u16>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let (outgoing, queued) = mpsc::channel::<Vec<u8>>(OUTGOING_FRAMES);
    let writer = tokio::spawn(write_frames(writer, queued));
    let (mut session, opening) = SyncSession::start(vault, listen_port)?;
    for message in opening {
        outgoing
            .send(encode_frame(&message)?)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
    }
    while !session.is_complete() {
        let message = with_timeout(FRAME_TIMEOUT, read_frame(&mut reader)).await??;
        for reply in session.handle(vault, message)? {
            outgoing
                .send(encode_frame(&reply)?)
                .await
                .map_err(|_| Error::ConnectionClosed)?;
        }
    }
    // Closing the queue lets the writer flush what is left and shut down.
    drop(outgoing);
    writer.await.map_err(|_| Error::ConnectionClosed)??;
    Ok((session.report().clone(), session.peer_listen_port()))
}

async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queued: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(frame) = queued.recv().await {
        with_timeout(FRAME_TIMEOUT, writer.write_all(&frame))
            .await?
            .map_err(io_error)?;
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
    serde_json::from_slice(&read_body(reader).await?).map_err(|_| Error::MalformedFrame)
}

/// Reads one frame. The declared length is checked before the body is
/// allocated.
pub(crate) async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    decode_body(&read_body(reader).await?)
}

async fn read_body<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await.map_err(io_error)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await.map_err(io_error)?;
    Ok(body)
}

async fn connect_first(addresses: &[String]) -> Result<TcpStream> {
    let mut last = Error::InvalidAddress;
    for address in addresses {
        match with_timeout(CONNECT_TIMEOUT, TcpStream::connect(address.as_str())).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = Error::Io(error),
            Err(error) => last = error,
        }
    }
    Err(last)
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

fn certificate(
    identity: &TransportIdentity,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(identity.certificate.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key.to_vec())),
    )
}

/// Decides at each handshake whether a client certificate is accepted.
pub(crate) trait PinPolicy: Send + Sync + std::fmt::Debug {
    fn accepts(&self, pin: &[u8; 32]) -> bool;
}

#[derive(Debug)]
pub(crate) enum ClientPolicy {
    /// Pairing: any certificate, checked afterwards against the request.
    AnyForPairing,
    /// Sync: only the paired devices' certificates.
    Pinned(Vec<[u8; 32]>),
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
    let (chain, key) = certificate(identity);
    let mut config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Transport("TLS 1.3 is unavailable"))?
        .with_client_cert_verifier(Arc::new(PinnedClients {
            policy: clients,
            provider,
        }))
        .with_single_cert(chain, key)
        .map_err(|_| Error::Transport("invalid transport certificate"))?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

pub(crate) fn client_config(
    identity: &TransportIdentity,
    server_pin: [u8; 32],
) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let (chain, key) = certificate(identity);
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Transport("TLS 1.3 is unavailable"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            pin: server_pin,
            provider,
        }))
        .with_client_auth_cert(chain, key)
        .map_err(|_| Error::Transport("invalid transport certificate"))?;
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
                ClientPolicy::Pinned(pins) => pins.contains(&pin_of(end_entity)),
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
