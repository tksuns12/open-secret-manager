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

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

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
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use osm_vault_membership::SignedRequest;

use crate::{
    approve_enrollment,
    members::MemberContact,
    pairing::JoinReview,
    peers::{pin_of, TransportIdentity},
    review_join,
    wire::{decode_body, encode_frame, MAX_FRAME_BYTES},
    EnrollmentGrant, Error, Invitation, JoinRequest, Joiner, PeerStore, Result, SyncReport,
    SyncSession, MAX_INVITATION_TTL_SECS,
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
        }
    }
}

/// A join request ready to send. Preparing it needs the peer store, and for
/// a device joining with its vault, the vault; connecting needs neither.
pub struct PreparedJoin {
    joiner: Joiner,
    request: JoinRequest,
    identity: TransportIdentity,
}

impl PreparedJoin {
    /// The request of a new device, which has no vault yet.
    pub fn new(invitation: Invitation, peers: &mut PeerStore, now: u64) -> Result<Self> {
        let identity = peers.transport_identity()?;
        let (joiner, request) = Joiner::start(invitation, identity.pin(), now)?;
        Ok(Self {
            joiner,
            request,
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
        let (joiner, request) = Joiner::start_with_vault(invitation, vault, identity.pin(), now)?;
        Ok(Self {
            joiner,
            request,
            identity,
        })
    }

    /// Connects to the inviter named in the invitation, pinning its
    /// certificate, and sends the request.
    pub async fn connect(self) -> Result<PairingConnection> {
        let joiner = self.joiner;
        let connector = TlsConnector::from(client_config(
            &self.identity,
            joiner.inviter_transport_pin(),
        )?);
        let tcp = connect_first(joiner.inviter_addresses()).await?;
        let mut stream = with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
            .await?
            .map_err(handshake_error)?;
        write_frame(&mut stream, &self.request).await?;
        Ok(PairingConnection { joiner, stream })
    }
}

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
/// the port the peer says it listens on. Reading and writing run
/// concurrently, so two peers sending large batches at once cannot block
/// each other on full socket buffers.
pub(crate) async fn run_session<S, V>(
    stream: S,
    vault: &V,
    listen_port: Option<u16>,
) -> Result<(SyncReport, Option<u16>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    V: SharedVault + ?Sized,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let (outgoing, queued) = mpsc::channel::<Vec<u8>>(OUTGOING_FRAMES);
    let writer = tokio::spawn(write_frames(writer, queued));
    let (mut session, opening) = vault
        .with(|vault| SyncSession::start(vault, listen_port))
        .await
        .ok_or(NO_VAULT)??;
    for message in opening {
        outgoing
            .send(encode_frame(&message)?)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
    }
    while !session.is_complete() {
        let message = with_timeout(FRAME_TIMEOUT, read_frame(&mut reader)).await??;
        // The vault is held only while this message is handled, never
        // while waiting for the peer.
        let replies = vault
            .with(|vault| session.handle(vault, message))
            .await
            .ok_or(NO_VAULT)??;
        for reply in replies {
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
