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

use std::{future::Future, sync::Arc, time::Duration};

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

use crate::{
    approve_join,
    peers::{pin_of, TransportIdentity},
    review_join,
    wire::{decode_body, encode_frame, MAX_FRAME_BYTES},
    Error, Invitation, JoinGrant, JoinRequest, Joiner, PeerStore, Result, SyncReport, SyncSession,
    MAX_INVITATION_TTL_SECS,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for one frame from a peer during sync.
const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
/// The joiner waits this long for the owner to confirm on the inviter.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(MAX_INVITATION_TTL_SECS);
const OUTGOING_FRAMES: usize = 16;

#[derive(Serialize, Deserialize)]
enum PairingReply {
    Grant(JoinGrant),
    Declined,
}

/// Waits for a joiner, asks the owner to confirm the short code with
/// `confirm`, and sends the grant. Connections that fail before the owner is
/// asked (bad handshake, invalid or replayed request) are dropped and the
/// listener keeps waiting until the invitation window closes. Returns
/// `NotConfirmed` if the owner declines.
pub async fn accept_pairing<C, F>(
    listener: &TcpListener,
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
    let identity = peers.transport_identity()?;
    let acceptor = TlsAcceptor::from(server_config(&identity, ClientPolicy::AnyForPairing)?);
    let deadline = tokio::time::Instant::now() + PAIRING_TIMEOUT;
    loop {
        let (tcp, _) = tokio::time::timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| Error::Timeout)??;
        match pairing_connection(
            tcp,
            &acceptor,
            vault,
            invitations,
            peers,
            &mut confirm,
            &clock,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(Error::NotConfirmed) => return Err(Error::NotConfirmed),
            // Anything else was not a pairing the owner could approve.
            Err(_) => continue,
        }
    }
}

async fn pairing_connection<C, F>(
    tcp: TcpStream,
    acceptor: &TlsAcceptor,
    vault: &mut Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    confirm: &mut C,
    clock: &impl Fn() -> u64,
) -> Result<()>
where
    C: FnMut(String) -> F,
    F: Future<Output = bool>,
{
    let mut stream = with_timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
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
    // The request is signed by the joiner's device key; the certificate on
    // this connection must be the one it names.
    if request.joiner_transport_pin() != client_pin {
        return Err(Error::PinMismatch);
    }
    let review = review_join(vault, invitations, peers, request, clock())?;
    if !confirm(review.sas()).await {
        write_frame(&mut stream, &PairingReply::Declined).await?;
        let _ = stream.shutdown().await;
        return Err(Error::NotConfirmed);
    }
    let grant = approve_join(vault, invitations, peers, review, clock())?;
    write_frame(&mut stream, &PairingReply::Grant(grant)).await?;
    let _ = stream.shutdown().await;
    Ok(())
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

/// Accepts one connection from the paired device and runs a sync session.
/// A client presenting any other certificate is refused during the
/// handshake.
pub async fn serve_sync(
    listener: &TcpListener,
    vault: &mut Vault,
    peers: &mut PeerStore,
) -> Result<SyncReport> {
    let identity = peers.transport_identity()?;
    let pins: Vec<[u8; 32]> = peers
        .peers()?
        .iter()
        .map(|peer| peer.transport_pin)
        .collect();
    if pins.is_empty() {
        return Err(Error::NotPaired);
    }
    let acceptor = TlsAcceptor::from(server_config(&identity, ClientPolicy::Pinned(pins))?);
    let (tcp, _) = listener.accept().await?;
    let stream = with_timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await?
        .map_err(handshake_error)?;
    run_session(stream, vault).await
}

/// Connects to the paired device at `address`, pinning its certificate, and
/// runs a sync session.
pub async fn connect_sync(
    address: &str,
    vault: &mut Vault,
    peers: &mut PeerStore,
) -> Result<SyncReport> {
    let identity = peers.transport_identity()?;
    let peer = peers.peers()?.into_iter().next().ok_or(Error::NotPaired)?;
    let connector = TlsConnector::from(client_config(&identity, peer.transport_pin)?);
    let tcp = connect_first(&[address.to_owned()]).await?;
    let stream = with_timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name(), tcp))
        .await?
        .map_err(handshake_error)?;
    run_session(stream, vault).await
}

/// Drives a [`SyncSession`] over a byte stream. Reading and writing run
/// concurrently, so two peers sending large batches at once cannot block
/// each other on full socket buffers.
pub(crate) async fn run_session<S>(stream: S, vault: &mut Vault) -> Result<SyncReport>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let (outgoing, queued) = mpsc::channel::<Vec<u8>>(OUTGOING_FRAMES);
    let writer = tokio::spawn(write_frames(writer, queued));
    let (mut session, opening) = SyncSession::start(vault)?;
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
    Ok(session.report().clone())
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

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &impl Serialize,
) -> Result<()> {
    let frame = encode_frame(message)?;
    with_timeout(FRAME_TIMEOUT, writer.write_all(&frame))
        .await?
        .map_err(io_error)
}

/// Reads one frame. The declared length is checked before the body is
/// allocated.
pub(crate) async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await.map_err(io_error)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await.map_err(io_error)?;
    decode_body(&body)
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

async fn with_timeout<T>(limit: Duration, future: impl Future<Output = T>) -> Result<T> {
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
fn handshake_error(error: std::io::Error) -> Error {
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
fn server_name() -> ServerName<'static> {
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

enum ClientPolicy {
    /// Pairing: any certificate, checked afterwards against the request.
    AnyForPairing,
    /// Sync: only the paired devices' certificates.
    Pinned(Vec<[u8; 32]>),
}

fn server_config(identity: &TransportIdentity, clients: ClientPolicy) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let (chain, key) = certificate(identity);
    let mut config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Transport("TLS 1.3 is unavailable"))?
        .with_client_cert_verifier(Arc::new(PinnedClients {
            pins: match clients {
                ClientPolicy::AnyForPairing => None,
                ClientPolicy::Pinned(pins) => Some(pins),
            },
            provider,
        }))
        .with_single_cert(chain, key)
        .map_err(|_| Error::Transport("invalid transport certificate"))?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

fn client_config(identity: &TransportIdentity, server_pin: [u8; 32]) -> Result<Arc<ClientConfig>> {
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

/// Requires a client certificate; with `pins`, only one of those hashes.
#[derive(Debug)]
struct PinnedClients {
    pins: Option<Vec<[u8; 32]>>,
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
        match &self.pins {
            Some(pins) => check_pin(end_entity, intermediates, pins)?,
            None if intermediates.is_empty() => {}
            None => {
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
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
