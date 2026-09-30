//! Owner-confirmed pairing of a new device with an existing vault.
//!
//! 1. The inviter issues an [`Invitation`] and shows it out of band (for
//!    example as a QR code). It carries a one-use token and the inviter's
//!    device key, which the joiner pins.
//! 2. The joiner creates its own device identity and a [`JoinRequest`] signed
//!    with it, bound to a transcript of both identities and the token.
//! 3. The inviter reviews the request. Both devices display the same short
//!    code derived from the transcript, and the owner compares them.
//! 4. After the owner confirms, the inviter consumes the token, authorizes
//!    the joiner as a revision author, and returns a signed [`JoinGrant`]
//!    carrying the vault key sealed to the joiner with HPKE.
//! 5. After the owner confirms on the joiner too, it verifies the grant and
//!    creates its own copy of the vault. Revisions then arrive by sync.

use base64ct::{Base64UrlUnpadded, Encoding};
use osm_vault_core::{verify_pairing_signature, EnrollmentMaterial, PendingDevice, Vault};
use osm_vault_sync::{
    open_epoch_key, seal_epoch_key, DeviceId, EpochKeyEnvelope, HpkeKeyPair, HpkePublicKey,
    InvitationStore, InvitationToken, VaultId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, PeerStore, Result};

const PAIRING_VERSION: u8 = 1;
const INVITATION_PREFIX: &str = "OSM-PAIR1-";
const MAX_INVITATION_CODE_LEN: usize = 512;
const MAX_GRANT_DEVICES: usize = 64;
const RECOVERY_WRAPPED_KEY_LEN: usize = 48;

/// Invitations are shown on screen and must be used promptly.
pub const MAX_INVITATION_TTL_SECS: u64 = 15 * 60;

#[derive(Serialize, Deserialize)]
struct InvitationBody {
    version: u8,
    vault_id: [u8; 32],
    inviter_device_id: [u8; 16],
    inviter_public_key: [u8; 32],
    token: [u8; 32],
    expires_at: u64,
}

/// An out-of-band invitation. It contains a bearer token, so it is never
/// logged and is zeroized on drop.
pub struct Invitation {
    body: InvitationBody,
}

impl Drop for Invitation {
    fn drop(&mut self) {
        self.body.token.zeroize();
    }
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invitation")
            .field("expires_at", &self.body.expires_at)
            .finish_non_exhaustive()
    }
}

impl Invitation {
    /// The text form shown to the owner, `OSM-PAIR1-` plus base64url.
    pub fn encode(&self) -> Result<Zeroizing<String>> {
        let bytes = Zeroizing::new(
            postcard::to_allocvec(&self.body).map_err(|_| Error::InvalidInvitation)?,
        );
        Ok(Zeroizing::new(format!(
            "{INVITATION_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&bytes)
        )))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let code = code.trim();
        if code.len() > MAX_INVITATION_CODE_LEN {
            return Err(Error::InvalidInvitation);
        }
        let encoded = code
            .strip_prefix(INVITATION_PREFIX)
            .ok_or(Error::InvalidInvitation)?;
        let bytes = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(encoded).map_err(|_| Error::InvalidInvitation)?,
        );
        let (body, rest): (InvitationBody, _) =
            postcard::take_from_bytes(&bytes).map_err(|_| Error::InvalidInvitation)?;
        let invitation = Self { body };
        if !rest.is_empty() {
            return Err(Error::InvalidInvitation);
        }
        if invitation.body.version != PAIRING_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(invitation)
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.body.vault_id
    }

    pub fn expires_at(&self) -> u64 {
        self.body.expires_at
    }
}

/// Sent by the joiner to the inviter.
#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    version: u8,
    vault_id: [u8; 32],
    token: [u8; 32],
    joiner_device_id: [u8; 16],
    joiner_public_key: [u8; 32],
    joiner_hpke_key: [u8; 32],
    /// Joiner's pairing signature over the transcript.
    signature: Vec<u8>,
}

impl Drop for JoinRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl JoinRequest {
    #[cfg(test)]
    pub(crate) fn tamper_signature(&mut self) {
        self.signature[0] ^= 1;
    }
}

impl std::fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinRequest")
            .field("joiner_device_id", &self.joiner_device_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: [u8; 16],
    pub public_key: [u8; 32],
}

/// Sent by the inviter after the owner confirms. `envelope` is the vault key
/// sealed to the joiner's HPKE key; nothing here is secret without it.
#[derive(Serialize, Deserialize)]
pub struct JoinGrant {
    version: u8,
    vault_id: [u8; 32],
    key_epoch: u64,
    envelope: Vec<u8>,
    recovery_nonce: [u8; 24],
    recovery_wrapped_key: Vec<u8>,
    devices: Vec<DeviceEntry>,
    /// Inviter's pairing signature over the transcript and every field.
    signature: Vec<u8>,
}

impl JoinGrant {
    fn signed_message(&self, transcript: &[u8; 32]) -> Vec<u8> {
        let mut message = b"join-grant\0".to_vec();
        message.extend_from_slice(transcript);
        message.push(self.version);
        message.extend_from_slice(&self.vault_id);
        message.extend_from_slice(&self.key_epoch.to_be_bytes());
        push_field(&mut message, &self.envelope);
        message.extend_from_slice(&self.recovery_nonce);
        push_field(&mut message, &self.recovery_wrapped_key);
        message.extend_from_slice(&(self.devices.len() as u64).to_be_bytes());
        for device in &self.devices {
            message.extend_from_slice(&device.device_id);
            message.extend_from_slice(&device.public_key);
        }
        message
    }

    #[cfg(test)]
    pub(crate) fn tamper_devices(&mut self) {
        self.devices.pop();
    }
}

/// A verified join request awaiting the owner's decision on the inviter.
pub struct JoinReview {
    request: JoinRequest,
    transcript: [u8; 32],
}

impl JoinReview {
    /// The short code to compare with the joiner's screen.
    pub fn sas(&self) -> String {
        short_code(&self.transcript)
    }

    pub fn joiner_device_id(&self) -> [u8; 16] {
        self.request.joiner_device_id
    }
}

/// Issues a pairing invitation valid for `ttl_secs` (at most
/// [`MAX_INVITATION_TTL_SECS`]).
pub fn invite(
    vault: &Vault,
    invitations: &mut InvitationStore,
    peers: &PeerStore,
    now: u64,
    ttl_secs: u64,
) -> Result<Invitation> {
    if ttl_secs == 0 || ttl_secs > MAX_INVITATION_TTL_SECS {
        return Err(Error::InvalidInvitation);
    }
    peers.ensure_capacity()?;
    let (device_id, public_key) = own_identity(vault)?;
    let expires_at = now.checked_add(ttl_secs).ok_or(Error::InvalidInvitation)?;
    let token = invitations.issue_pairing(VaultId(vault.vault_id()), now, expires_at)?;
    Ok(Invitation {
        body: InvitationBody {
            version: PAIRING_VERSION,
            vault_id: vault.vault_id(),
            inviter_device_id: device_id,
            inviter_public_key: public_key,
            token: *token.expose_secret(),
            expires_at,
        },
    })
}

/// Validates a join request without consuming the invitation. Only a request
/// that carries a live token and is signed by the key it names reaches the
/// owner for confirmation.
pub fn review_join(
    vault: &Vault,
    invitations: &InvitationStore,
    request: JoinRequest,
    now: u64,
) -> Result<JoinReview> {
    if request.version != PAIRING_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if request.vault_id != vault.vault_id() {
        return Err(Error::VaultMismatch);
    }
    let token = InvitationToken::from_bytes(request.token);
    if invitations.check(&token, now)? != VaultId(vault.vault_id()) {
        return Err(Error::VaultMismatch);
    }
    let (inviter_id, inviter_key) = own_identity(vault)?;
    let transcript = transcript(
        &request.vault_id,
        &inviter_id,
        &inviter_key,
        &request.token,
        &request.joiner_device_id,
        &request.joiner_public_key,
        &request.joiner_hpke_key,
    );
    verify_pairing_signature(
        &request.joiner_public_key,
        &request_message(&transcript),
        &request.signature,
    )
    .map_err(|_| Error::InvalidSignature)?;
    Ok(JoinReview {
        request,
        transcript,
    })
}

/// Completes pairing on the inviter. Call only after the owner confirmed
/// that both devices show the same short code.
///
/// The grant is built before any side effect, then the token is consumed so
/// it cannot be replayed, and only then is the joiner authorized.
pub fn approve_join(
    vault: &mut Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    review: JoinReview,
    now: u64,
) -> Result<JoinGrant> {
    peers.ensure_capacity()?;
    let request = &review.request;
    let material = vault.enrollment_material()?;
    let envelope = seal_epoch_key(
        VaultId(material.vault_id),
        material.key_epoch,
        DeviceId(request.joiner_public_key),
        HpkePublicKey::from_bytes(request.joiner_hpke_key)?,
        &material.master_key,
    )?;
    let mut grant = JoinGrant {
        version: PAIRING_VERSION,
        vault_id: material.vault_id,
        key_epoch: material.key_epoch,
        envelope: envelope.to_bytes().to_vec(),
        recovery_nonce: material.recovery_nonce,
        recovery_wrapped_key: material.recovery_wrapped_key.clone(),
        devices: material
            .devices
            .iter()
            .map(|(device_id, public_key)| DeviceEntry {
                device_id: *device_id,
                public_key: *public_key,
            })
            .collect(),
        signature: Vec::new(),
    };
    grant.signature = vault
        .sign_pairing(&grant.signed_message(&review.transcript))?
        .to_vec();

    invitations.approve(
        &InvitationToken::from_bytes(request.token),
        DeviceId(request.joiner_public_key),
        now,
    )?;
    vault.authorize_device(request.joiner_device_id, request.joiner_public_key)?;
    peers.add(request.joiner_device_id, request.joiner_public_key, now)?;
    Ok(grant)
}

/// The joining device's side of pairing.
pub struct Joiner {
    invitation: Invitation,
    device: PendingDevice,
    hpke: HpkeKeyPair,
    transcript: [u8; 32],
}

impl Joiner {
    /// Creates this device's identity and the request to send.
    pub fn start(invitation: Invitation, now: u64) -> Result<(Self, JoinRequest)> {
        if now >= invitation.body.expires_at {
            return Err(Error::InvitationExpired);
        }
        let device = PendingDevice::generate();
        let hpke = HpkeKeyPair::generate()?;
        let body = &invitation.body;
        let transcript = transcript(
            &body.vault_id,
            &body.inviter_device_id,
            &body.inviter_public_key,
            &body.token,
            &device.device_id(),
            &device.public_key(),
            &hpke.public().as_bytes(),
        );
        let request = JoinRequest {
            version: PAIRING_VERSION,
            vault_id: body.vault_id,
            token: body.token,
            joiner_device_id: device.device_id(),
            joiner_public_key: device.public_key(),
            joiner_hpke_key: hpke.public().as_bytes(),
            signature: device.sign_pairing(&request_message(&transcript)).to_vec(),
        };
        Ok((
            Self {
                invitation,
                device,
                hpke,
                transcript,
            },
            request,
        ))
    }

    /// The short code to compare with the inviter's screen.
    pub fn sas(&self) -> String {
        short_code(&self.transcript)
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device.device_id()
    }

    /// Verifies the grant and creates this device's vault at `path`. Call
    /// with `owner_confirmed` only after the owner compared the short codes.
    pub fn finish(
        self,
        grant: &JoinGrant,
        owner_confirmed: bool,
        path: impl AsRef<std::path::Path>,
        password: &str,
        peers: &mut PeerStore,
        now: u64,
    ) -> Result<Vault> {
        if !owner_confirmed {
            return Err(Error::NotConfirmed);
        }
        let body = &self.invitation.body;
        if grant.version != PAIRING_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if grant.vault_id != body.vault_id {
            return Err(Error::VaultMismatch);
        }
        // The inviter's key came from the invitation, not from the channel.
        verify_pairing_signature(
            &body.inviter_public_key,
            &grant.signed_message(&self.transcript),
            &grant.signature,
        )
        .map_err(|_| Error::InvalidSignature)?;
        let inviter = DeviceEntry {
            device_id: body.inviter_device_id,
            public_key: body.inviter_public_key,
        };
        if grant.devices.len() > MAX_GRANT_DEVICES
            || !grant.devices.contains(&inviter)
            || grant.recovery_wrapped_key.len() != RECOVERY_WRAPPED_KEY_LEN
        {
            return Err(Error::ProtocolViolation);
        }
        let envelope = EpochKeyEnvelope::from_bytes(&grant.envelope)?;
        let master_key = open_epoch_key(
            &envelope,
            VaultId(grant.vault_id),
            grant.key_epoch,
            DeviceId(self.device.public_key()),
            self.hpke.private(),
        )?;
        peers.ensure_capacity()?;
        let material = EnrollmentMaterial {
            vault_id: grant.vault_id,
            key_epoch: grant.key_epoch,
            master_key,
            recovery_nonce: grant.recovery_nonce,
            recovery_wrapped_key: grant.recovery_wrapped_key.clone(),
            devices: grant
                .devices
                .iter()
                .map(|device| (device.device_id, device.public_key))
                .collect(),
        };
        let (inviter_id, inviter_key) = (inviter.device_id, inviter.public_key);
        let vault = Vault::join(path, password, self.device, material)?;
        peers.add(inviter_id, inviter_key, now)?;
        Ok(vault)
    }
}

fn own_identity(vault: &Vault) -> Result<([u8; 16], [u8; 32])> {
    Ok((
        vault.device_id().ok_or(osm_vault_core::Error::Locked)?,
        vault
            .device_public_key()
            .ok_or(osm_vault_core::Error::Locked)?,
    ))
}

/// Hash of everything both sides must agree on. Every field is fixed length.
fn transcript(
    vault_id: &[u8; 32],
    inviter_device_id: &[u8; 16],
    inviter_public_key: &[u8; 32],
    token: &[u8; 32],
    joiner_device_id: &[u8; 16],
    joiner_public_key: &[u8; 32],
    joiner_hpke_key: &[u8; 32],
) -> [u8; 32] {
    let token_digest = Sha256::new()
        .chain_update(b"osm-pairing-token-v1\0")
        .chain_update(token)
        .finalize();
    Sha256::new()
        .chain_update(b"osm-pairing-transcript-v1\0")
        .chain_update(vault_id)
        .chain_update(inviter_device_id)
        .chain_update(inviter_public_key)
        .chain_update(token_digest)
        .chain_update(joiner_device_id)
        .chain_update(joiner_public_key)
        .chain_update(joiner_hpke_key)
        .finalize()
        .into()
}

fn request_message(transcript: &[u8; 32]) -> Vec<u8> {
    let mut message = b"join-request\0".to_vec();
    message.extend_from_slice(transcript);
    message
}

/// Six decimal digits, shown as `123 456`.
fn short_code(transcript: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"osm-pairing-sas-v1\0")
        .chain_update(transcript)
        .finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", value / 1000, value % 1000)
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}
