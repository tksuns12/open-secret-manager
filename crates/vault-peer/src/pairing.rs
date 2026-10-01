//! Owner-confirmed pairing of a new device with an existing vault.
//!
//! 1. The inviter issues an [`Invitation`] and shows it out of band (for
//!    example as a QR code). It carries a one-use token and the inviter's
//!    device key, which the joiner pins.
//! 2. The joiner creates its own device identity, including the HPKE
//!    recipient key it keeps for life, and a [`JoinRequest`] signed with it,
//!    bound to a transcript of both identities and the token.
//! 3. The inviter reviews the request. Both devices display the same short
//!    code derived from the transcript, and the owner compares them.
//! 4. After the owner confirms, the inviter consumes the token and proposes
//!    enrolling the joiner to the vault's control plane
//!    ([`approve_enrollment`]). Once a quorum has committed the proposal, it
//!    sends a signed [`EnrollmentGrant`] naming it and the vault's members.
//! 5. The joiner has no log yet, so it accepts control connections from the
//!    members the grant names ([`Joiner::members`]) and tells them where it
//!    listens. Its control-plane node catches up as a learner and becomes a
//!    voter; a member then grants it every epoch key, sealed to its
//!    recipient key in committed state. After the owner confirms on the
//!    joiner too, it creates its own copy of the vault from that state
//!    ([`Joiner::finish_enrollment`]). Revisions then arrive by sync.
//!
//! Until the desktop app runs the control plane, it still uses the interim
//! path: [`approve_join`] authorizes the joiner directly and returns a
//! [`JoinGrant`] carrying the epoch keys, and [`Joiner::finish`] completes
//! it, with at most one paired device. It must not be used on a vault whose
//! control plane has been founded.

use base64ct::{Base64UrlUnpadded, Encoding};
use osm_vault_core::{
    epoch_key_check, verify_pairing_signature, EnrollmentMaterial, PendingDevice, Vault,
};
use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlState, DeviceNode, SignedRequest,
};
use osm_vault_sync::{
    open_epoch_key, seal_epoch_key, DeviceId, EpochKeyEnvelope, HpkeKeyPair, HpkePublicKey,
    InvitationStore, InvitationToken, VaultId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    control,
    members::{valid_contacts, MemberContact},
    Error, Peer, PeerStore, Result,
};

const PAIRING_VERSION: u8 = 1;
const INVITATION_PREFIX: &str = "OSM-PAIR1-";
const MAX_INVITATION_CODE_LEN: usize = 512;
const MAX_GRANT_DEVICES: usize = 64;
const MAX_GRANT_EPOCHS: usize = 1024;
const MAX_ADDRESSES: usize = 4;
const MAX_ADDRESS_LEN: usize = 128;

/// Invitations are shown on screen and must be used promptly.
pub const MAX_INVITATION_TTL_SECS: u64 = 15 * 60;

#[derive(Serialize, Deserialize)]
struct InvitationBody {
    version: u8,
    vault_id: [u8; 32],
    inviter_device_id: [u8; 16],
    inviter_public_key: [u8; 32],
    /// SHA-256 of the inviter's TLS certificate; the joiner pins it.
    inviter_transport_pin: [u8; 32],
    /// Where the inviter listens. Advisory: the pin, not the address,
    /// authenticates the inviter.
    addresses: Vec<String>,
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
        if !valid_addresses(&invitation.body.addresses) {
            return Err(Error::InvalidInvitation);
        }
        Ok(invitation)
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.body.vault_id
    }

    pub fn expires_at(&self) -> u64 {
        self.body.expires_at
    }

    pub fn inviter_transport_pin(&self) -> [u8; 32] {
        self.body.inviter_transport_pin
    }

    pub fn addresses(&self) -> &[String] {
        &self.body.addresses
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
    /// SHA-256 of the joiner's TLS certificate. The inviter checks it
    /// against the certificate the connection presented.
    joiner_transport_pin: [u8; 32],
    /// Joiner's pairing signature over the transcript.
    signature: Vec<u8>,
}

impl Drop for JoinRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl JoinRequest {
    pub fn joiner_transport_pin(&self) -> [u8; 32] {
        self.joiner_transport_pin
    }

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
    /// The epoch the joiner writes under.
    current_epoch: u64,
    /// One HPKE envelope per epoch key, sealed to the joiner. Each names its
    /// epoch. The inviter's root key is never sent.
    envelopes: Vec<Vec<u8>>,
    /// Lets the joiner verify the recovery key before enabling recovery.
    recovery_check: Option<[u8; 32]>,
    devices: Vec<DeviceEntry>,
    /// Port the inviter accepts sync connections on, if it listens. The
    /// joiner pairs it with the inviter's address from the invitation; the
    /// pairing port itself closes after pairing.
    inviter_sync_port: Option<u16>,
    /// Inviter's pairing signature over the transcript and every field.
    signature: Vec<u8>,
}

impl JoinGrant {
    fn signed_message(&self, transcript: &[u8; 32]) -> Vec<u8> {
        let mut message = b"join-grant\0".to_vec();
        message.extend_from_slice(transcript);
        message.push(self.version);
        message.extend_from_slice(&self.vault_id);
        message.extend_from_slice(&self.current_epoch.to_be_bytes());
        message.extend_from_slice(&(self.envelopes.len() as u64).to_be_bytes());
        for envelope in &self.envelopes {
            push_field(&mut message, envelope);
        }
        match &self.recovery_check {
            Some(check) => {
                message.push(1);
                message.extend_from_slice(check);
            }
            None => message.push(0),
        }
        message.extend_from_slice(&(self.devices.len() as u64).to_be_bytes());
        for device in &self.devices {
            message.extend_from_slice(&device.device_id);
            message.extend_from_slice(&device.public_key);
        }
        match self.inviter_sync_port {
            Some(port) => {
                message.push(1);
                message.extend_from_slice(&port.to_be_bytes());
            }
            None => message.push(0),
        }
        message
    }

    #[cfg(test)]
    pub(crate) fn tamper_devices(&mut self) {
        self.devices.pop();
    }
}

/// Sent by the inviter once the joiner's enrollment proposal is committed.
/// The keys themselves reach the joiner through committed control state
/// after it has become a voter, so nothing here is secret.
#[derive(Serialize, Deserialize)]
pub struct EnrollmentGrant {
    version: u8,
    vault_id: [u8; 32],
    /// The committed proposal that enrolls the joiner.
    request_id: [u8; 16],
    /// Lets the joiner verify the recovery key before enabling recovery.
    recovery_check: Option<[u8; 32]>,
    /// The vault's members, the inviter among them. The joiner has no log
    /// to tell it whose control connections to accept, and the leader that
    /// brings it up to date need not be the inviter.
    members: Vec<MemberContact>,
    /// Port the inviter accepts member connections on, if it listens. The
    /// joiner pairs it with the inviter's address from the invitation.
    inviter_port: Option<u16>,
    /// Inviter's pairing signature over the transcript and every field.
    signature: Vec<u8>,
}

impl EnrollmentGrant {
    fn signed_message(&self, transcript: &[u8; 32]) -> Vec<u8> {
        let mut message = b"enrollment-grant\0".to_vec();
        message.extend_from_slice(transcript);
        message.push(self.version);
        message.extend_from_slice(&self.vault_id);
        message.extend_from_slice(&self.request_id);
        match &self.recovery_check {
            Some(check) => {
                message.push(1);
                message.extend_from_slice(check);
            }
            None => message.push(0),
        }
        message.extend_from_slice(&(self.members.len() as u64).to_be_bytes());
        for member in &self.members {
            message.extend_from_slice(&member.device_id);
            message.extend_from_slice(&member.transport_pin);
            match &member.address {
                Some(address) => {
                    message.push(1);
                    push_field(&mut message, address.as_bytes());
                }
                None => message.push(0),
            }
        }
        match self.inviter_port {
            Some(port) => {
                message.push(1);
                message.extend_from_slice(&port.to_be_bytes());
            }
            None => message.push(0),
        }
        message
    }

    /// The enrollment proposal, for cancelling it if the joiner never
    /// appears.
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
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

    /// The joiner as committed membership will record it.
    pub fn joiner_node(&self) -> DeviceNode {
        DeviceNode {
            public_key: self.request.joiner_public_key,
            transport_pin: self.request.joiner_transport_pin,
            recipient_key: self.request.joiner_hpke_key,
        }
    }
}

/// Issues a pairing invitation valid for `ttl_secs` (at most
/// [`MAX_INVITATION_TTL_SECS`]) naming the addresses this device listens on.
pub fn invite(
    vault: &Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    addresses: Vec<String>,
    now: u64,
    ttl_secs: u64,
) -> Result<Invitation> {
    if ttl_secs == 0 || ttl_secs > MAX_INVITATION_TTL_SECS {
        return Err(Error::InvalidInvitation);
    }
    if !valid_addresses(&addresses) {
        return Err(Error::InvalidAddress);
    }
    let transport_pin = peers.transport_identity()?.pin();
    let (device_id, public_key) = own_identity(vault)?;
    let expires_at = now.checked_add(ttl_secs).ok_or(Error::InvalidInvitation)?;
    let token = invitations.issue_pairing(VaultId(vault.vault_id()), now, expires_at)?;
    Ok(Invitation {
        body: InvitationBody {
            version: PAIRING_VERSION,
            vault_id: vault.vault_id(),
            inviter_device_id: device_id,
            inviter_public_key: public_key,
            inviter_transport_pin: transport_pin,
            addresses,
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
    peers: &mut PeerStore,
    request: JoinRequest,
    now: u64,
) -> Result<JoinReview> {
    let inviter_pin = peers.transport_identity()?.pin();
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
        &Inviter {
            vault_id: &request.vault_id,
            device_id: &inviter_id,
            public_key: &inviter_key,
            transport_pin: &inviter_pin,
            token: &request.token,
        },
        &request,
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

/// Approves a joiner on the inviter by proposing its enrollment. Call only
/// after the owner confirmed that both devices show the same short code.
///
/// The token is consumed so it cannot be replayed. Submit the returned
/// request to the control plane; once it is accepted, send the grant. If it
/// is refused, tell the joiner pairing failed; the owner starts over with a
/// new invitation.
///
/// `members` are the vault's members from this device's committed state,
/// this device included (`MemberEndpoint::roster`), and `listen_port` is
/// where this device accepts member connections, if it listens.
pub fn approve_enrollment(
    vault: &Vault,
    invitations: &mut InvitationStore,
    review: JoinReview,
    members: Vec<MemberContact>,
    listen_port: Option<u16>,
    now: u64,
) -> Result<(SignedRequest, EnrollmentGrant)> {
    if !valid_contacts(&members) {
        return Err(Error::InvalidAddress);
    }
    let request =
        control::enrollment_request(vault, review.request.joiner_device_id, review.joiner_node())?;
    let mut grant = EnrollmentGrant {
        version: PAIRING_VERSION,
        vault_id: vault.vault_id(),
        request_id: request.request_id,
        recovery_check: vault.recovery_check(),
        members,
        inviter_port: listen_port.filter(|port| *port != 0),
        signature: Vec::new(),
    };
    grant.signature = vault
        .sign_pairing(&grant.signed_message(&review.transcript))?
        .to_vec();
    invitations.approve(
        &InvitationToken::from_bytes(review.request.token),
        DeviceId(review.request.joiner_public_key),
        now,
    )?;
    Ok((request, grant))
}

/// Completes interim pairing on the inviter: the owner's confirmation
/// authorizes the joiner directly, with at most one paired device. Call
/// only after the owner confirmed that both devices show the same short
/// code, and never on a vault with a control plane.
///
/// The grant is built before any side effect, then the token is consumed so
/// it cannot be replayed, and only then is the joiner authorized.
/// `sync_port` is where this device accepts sync connections, if it listens.
pub fn approve_join(
    vault: &mut Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    review: JoinReview,
    sync_port: Option<u16>,
    now: u64,
) -> Result<JoinGrant> {
    peers.ensure_capacity()?;
    let request = &review.request;
    let material = vault.enrollment_material()?;
    let recipient_key = HpkePublicKey::from_bytes(request.joiner_hpke_key)?;
    let envelopes = material
        .epoch_keys
        .iter()
        .map(|(epoch, key)| {
            Ok(seal_epoch_key(
                VaultId(material.vault_id),
                *epoch,
                DeviceId(request.joiner_public_key),
                recipient_key,
                key,
            )?
            .to_bytes()
            .to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    let mut grant = JoinGrant {
        version: PAIRING_VERSION,
        vault_id: material.vault_id,
        current_epoch: material.current_epoch,
        envelopes,
        recovery_check: material.recovery_check,
        devices: material
            .devices
            .iter()
            .map(|(device_id, public_key)| DeviceEntry {
                device_id: *device_id,
                public_key: *public_key,
            })
            .collect(),
        inviter_sync_port: sync_port.filter(|port| *port != 0),
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
    peers.add(&Peer {
        device_id: request.joiner_device_id,
        public_key: request.joiner_public_key,
        transport_pin: request.joiner_transport_pin,
        address: None,
        paired_at: now,
    })?;
    Ok(grant)
}

/// The joining device's side of pairing.
pub struct Joiner {
    invitation: Invitation,
    device: PendingDevice,
    /// The device's long-lived recipient key, derived from the secret its
    /// vault will keep.
    hpke: HpkeKeyPair,
    transport_pin: [u8; 32],
    transcript: [u8; 32],
}

impl Joiner {
    /// Creates this device's identity and the request to send.
    /// `transport_pin` is this device's TLS certificate hash.
    pub fn start(
        invitation: Invitation,
        transport_pin: [u8; 32],
        now: u64,
    ) -> Result<(Self, JoinRequest)> {
        if now >= invitation.body.expires_at {
            return Err(Error::InvitationExpired);
        }
        let device = PendingDevice::generate();
        let hpke = HpkeKeyPair::from_secret(&device.recipient_secret());
        let body = &invitation.body;
        let mut request = JoinRequest {
            version: PAIRING_VERSION,
            vault_id: body.vault_id,
            token: body.token,
            joiner_device_id: device.device_id(),
            joiner_public_key: device.public_key(),
            joiner_hpke_key: hpke.public().as_bytes(),
            joiner_transport_pin: transport_pin,
            signature: Vec::new(),
        };
        let transcript = transcript(
            &Inviter {
                vault_id: &body.vault_id,
                device_id: &body.inviter_device_id,
                public_key: &body.inviter_public_key,
                transport_pin: &body.inviter_transport_pin,
                token: &body.token,
            },
            &request,
        );
        request.signature = device.sign_pairing(&request_message(&transcript)).to_vec();
        Ok((
            Self {
                invitation,
                device,
                hpke,
                transport_pin,
                transcript,
            },
            request,
        ))
    }

    /// This device's ID in the control plane. Start its control-plane node
    /// with it (and [`Joiner::vault_id`]) before the owner confirms, so the
    /// leader can bring it up to date as a learner.
    pub fn control_device(&self) -> osm_vault_membership::DeviceId {
        device_id_from_bytes(self.device.device_id())
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.invitation.body.vault_id
    }

    /// Whether committed control state lists this device as an enrolled
    /// voter holding every epoch key, so [`Joiner::finish_enrollment`] can
    /// proceed.
    pub fn enrolled(&self, state: &ControlState) -> bool {
        let me = self.control_device();
        state.epoch > 0
            && state.is_settled_member(me)
            && state.missing_epochs(me).is_empty()
            && state
                .envelopes
                .get(&me)
                .is_some_and(|sealed| (1..=state.epoch).all(|epoch| sealed.contains_key(&epoch)))
    }

    /// Checks that the grant is the invitation's inviter answering this
    /// pairing.
    fn verify_grant(&self, grant: &EnrollmentGrant) -> Result<()> {
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
        .map_err(|_| Error::InvalidSignature)
    }

    /// Verifies the grant and returns the vault's members as the inviter
    /// named them. Until this device has the log, these are the devices it
    /// accepts control connections from, so that whichever of them leads
    /// can bring it up to date; introduce them to its control-plane node.
    /// The inviter's own entry must carry the certificate from the
    /// invitation, and its address is the invitation's host with the port
    /// the grant names.
    pub fn members(&self, grant: &EnrollmentGrant) -> Result<Vec<MemberContact>> {
        self.verify_grant(grant)?;
        let body = &self.invitation.body;
        if !valid_contacts(&grant.members) {
            return Err(Error::ProtocolViolation);
        }
        let mut members = grant.members.clone();
        let inviter = members
            .iter_mut()
            .find(|member| member.device_id == body.inviter_device_id)
            .ok_or(Error::ProtocolViolation)?;
        if inviter.transport_pin != body.inviter_transport_pin {
            return Err(Error::ProtocolViolation);
        }
        inviter.address = grant
            .inviter_port
            .and_then(|port| sync_address(body.addresses.first(), Some(port)));
        Ok(members)
    }

    /// Verifies the grant and creates this device's vault at `path` from
    /// committed control state: its epoch keys come from the envelopes
    /// sealed to it, each checked against the committed key check, and its
    /// authors and removed devices from the state. Call with
    /// `owner_confirmed` only after the owner compared the short codes.
    /// Fails with `EnrollmentPending` until [`Joiner::enrolled`] holds.
    pub fn finish_enrollment(
        self,
        grant: &EnrollmentGrant,
        owner_confirmed: bool,
        state: &ControlState,
        path: impl AsRef<std::path::Path>,
        password: &str,
    ) -> Result<Vault> {
        if !owner_confirmed {
            return Err(Error::NotConfirmed);
        }
        self.verify_grant(grant)?;
        let body = &self.invitation.body;
        if state.vault_id != body.vault_id {
            return Err(Error::VaultMismatch);
        }
        if !self.enrolled(state) {
            return Err(Error::EnrollmentPending);
        }
        let me = self.control_device();
        let public_key = self.device.public_key();
        let recorded = state.node(me).ok_or(Error::EnrollmentPending)?;
        if recorded.public_key != public_key
            || recorded.recipient_key != self.hpke.public().as_bytes()
            || recorded.transport_pin != self.transport_pin
            || state.authors.get(&me) != Some(&public_key)
        {
            return Err(Error::ProtocolViolation);
        }
        let sealed = state.envelopes.get(&me).ok_or(Error::EnrollmentPending)?;
        let epoch_keys = (1..=state.epoch)
            .map(|epoch| {
                let envelope = sealed.get(&epoch).ok_or(Error::EnrollmentPending)?;
                let key = control::open(&body.vault_id, epoch, public_key, &self.hpke, envelope)?;
                if state.epoch_checks.get(&epoch)
                    != Some(&epoch_key_check(&body.vault_id, epoch, &key))
                {
                    return Err(Error::EpochKeyMismatch);
                }
                Ok((epoch, key))
            })
            .collect::<Result<Vec<_>>>()?;
        let material = EnrollmentMaterial {
            vault_id: body.vault_id,
            current_epoch: state.epoch,
            epoch_keys,
            recovery_check: grant.recovery_check,
            devices: state
                .authors
                .iter()
                .map(|(device, key)| (device_id_to_bytes(*device), *key))
                .collect(),
            revoked: state
                .removed
                .keys()
                .map(|device| device_id_to_bytes(*device))
                .collect(),
        };
        Ok(Vault::join(path, password, self.device, material)?)
    }

    /// The short code to compare with the inviter's screen.
    pub fn sas(&self) -> String {
        short_code(&self.transcript)
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device.device_id()
    }

    /// Verifies an interim grant and creates this device's vault at `path`.
    /// Call with `owner_confirmed` only after the owner compared the short
    /// codes.
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
            || grant.envelopes.is_empty()
            || grant.envelopes.len() > MAX_GRANT_EPOCHS
        {
            return Err(Error::ProtocolViolation);
        }
        // Each envelope is bound to this vault, its epoch, and this device;
        // `Vault::join` rejects duplicate epochs or a missing current one.
        let epoch_keys = grant
            .envelopes
            .iter()
            .map(|bytes| {
                let envelope = EpochKeyEnvelope::from_bytes(bytes)?;
                let key = open_epoch_key(
                    &envelope,
                    VaultId(grant.vault_id),
                    envelope.epoch(),
                    DeviceId(self.device.public_key()),
                    self.hpke.private(),
                )?;
                Ok((envelope.epoch(), key))
            })
            .collect::<Result<Vec<_>>>()?;
        peers.ensure_capacity()?;
        let material = EnrollmentMaterial {
            vault_id: grant.vault_id,
            current_epoch: grant.current_epoch,
            epoch_keys,
            recovery_check: grant.recovery_check,
            devices: grant
                .devices
                .iter()
                .map(|device| (device.device_id, device.public_key))
                .collect(),
            revoked: Vec::new(),
        };
        let peer = Peer {
            device_id: inviter.device_id,
            public_key: inviter.public_key,
            transport_pin: body.inviter_transport_pin,
            address: sync_address(body.addresses.first(), grant.inviter_sync_port),
            paired_at: now,
        };
        let vault = Vault::join(path, password, self.device, material)?;
        peers.add(&peer)?;
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

/// The inviter's half of the transcript, from the invitation.
struct Inviter<'a> {
    vault_id: &'a [u8; 32],
    device_id: &'a [u8; 16],
    public_key: &'a [u8; 32],
    transport_pin: &'a [u8; 32],
    token: &'a [u8; 32],
}

/// Hash of everything both sides must agree on, including both TLS pins, so
/// the short code also confirms the transport identities. Every field is
/// fixed length.
fn transcript(inviter: &Inviter<'_>, request: &JoinRequest) -> [u8; 32] {
    let token_digest = Sha256::new()
        .chain_update(b"osm-pairing-token-v1\0")
        .chain_update(inviter.token)
        .finalize();
    Sha256::new()
        .chain_update(b"osm-pairing-transcript-v1\0")
        .chain_update(inviter.vault_id)
        .chain_update(inviter.device_id)
        .chain_update(inviter.public_key)
        .chain_update(inviter.transport_pin)
        .chain_update(token_digest)
        .chain_update(request.joiner_device_id)
        .chain_update(request.joiner_public_key)
        .chain_update(request.joiner_hpke_key)
        .chain_update(request.joiner_transport_pin)
        .finalize()
        .into()
}

/// The inviter's sync address: its pairing host with the sync port from the
/// signed grant, or the pairing address if it named no sync port.
fn sync_address(pairing: Option<&String>, sync_port: Option<u16>) -> Option<String> {
    let pairing = pairing?;
    match (pairing.parse::<std::net::SocketAddr>(), sync_port) {
        (Ok(mut address), Some(port)) => {
            address.set_port(port);
            Some(address.to_string())
        }
        _ => Some(pairing.clone()),
    }
}

fn valid_addresses(addresses: &[String]) -> bool {
    addresses.len() <= MAX_ADDRESSES
        && addresses
            .iter()
            .all(|address| !address.is_empty() && address.len() <= MAX_ADDRESS_LEN)
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
