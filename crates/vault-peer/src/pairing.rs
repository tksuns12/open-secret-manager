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
//! A device that already holds a copy of the vault, paired before the vault
//! had a control plane, joins the same way under the identity it has
//! ([`Joiner::start_with_vault`], [`Joiner::finish_in_place`]): the owner
//! compares the codes, the device becomes a voter, and its vault is brought
//! in line with committed state instead of being created.

use base64ct::{Base64UrlUnpadded, Encoding};
use osm_vault_core::{
    epoch_key_check, verify_pairing_signature, EnrollmentMaterial, PendingDevice, Vault,
};
use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlState, DeviceNode, SignedRequest,
};
use osm_vault_sync::{DeviceId, HpkeKeyPair, InvitationStore, InvitationToken, VaultId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    control::{self, Reconciled, Voting},
    members::{valid_contacts, MemberContact},
    relay::RelayCode,
    Error, PeerStore, Result,
};

const PAIRING_VERSION: u8 = 1;
/// An invitation that also carries the relay the inviter is reached by.
const PAIRING_VERSION_WITH_RELAY: u8 = 2;
/// Version of the live pairing wire handshake (3-flight commit-before-reveal
/// binding both nonces, `voting`, and the invitation's relay).
pub const PAIRING_WIRE_VERSION: u8 = 2;
const INVITATION_PREFIX: &str = "OSM-PAIR1-";
const MAX_INVITATION_CODE_LEN: usize = 512;
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

/// Version 2 of the invitation: version 1's fields, then the relay the
/// inviter is reached by, so that a device away from the inviter's networks
/// can still join. Only issued on request; version 1 stays the default.
#[derive(Serialize, Deserialize)]
struct InvitationBodyWithRelay {
    version: u8,
    vault_id: [u8; 32],
    inviter_device_id: [u8; 16],
    inviter_public_key: [u8; 32],
    inviter_transport_pin: [u8; 32],
    addresses: Vec<String>,
    token: [u8; 32],
    expires_at: u64,
    relay_address: String,
    relay_pin: [u8; 32],
    relay_token: [u8; 32],
}

impl Drop for InvitationBodyWithRelay {
    fn drop(&mut self) {
        self.token.zeroize();
        self.relay_token.zeroize();
    }
}

/// An out-of-band invitation. It contains a bearer token, so it is never
/// logged and is zeroized on drop.
pub struct Invitation {
    body: InvitationBody,
    /// The relay of the vault, when the invitation names one.
    relay: Option<RelayCode>,
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
            match &self.relay {
                None => postcard::to_allocvec(&self.body),
                Some(relay) => postcard::to_allocvec(&InvitationBodyWithRelay {
                    version: PAIRING_VERSION_WITH_RELAY,
                    vault_id: self.body.vault_id,
                    inviter_device_id: self.body.inviter_device_id,
                    inviter_public_key: self.body.inviter_public_key,
                    inviter_transport_pin: self.body.inviter_transport_pin,
                    addresses: self.body.addresses.clone(),
                    token: self.body.token,
                    expires_at: self.body.expires_at,
                    relay_address: relay.address().to_owned(),
                    relay_pin: relay.pin(),
                    relay_token: *relay.token(),
                }),
            }
            .map_err(|_| Error::InvalidInvitation)?,
        );
        let code = Zeroizing::new(format!(
            "{INVITATION_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&bytes)
        ));
        // A code with a relay that the joiner could not read back is not
        // issued; a plain one is as it always was.
        if self.relay.is_some() && code.len() > MAX_INVITATION_CODE_LEN {
            return Err(Error::InvalidInvitation);
        }
        Ok(code)
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
        // The first byte is the version, in either form.
        let invitation = match bytes.first().copied() {
            Some(PAIRING_VERSION) => {
                let (body, rest): (InvitationBody, _) =
                    postcard::take_from_bytes(&bytes).map_err(|_| Error::InvalidInvitation)?;
                // Held from here, so that the token is wiped on every path.
                let invitation = Self { body, relay: None };
                // One form only: not a number written in more bytes than it needs.
                let one_form = postcard::to_allocvec(&invitation.body)
                    .map(Zeroizing::new)
                    .is_ok_and(|again| again.as_slice() == bytes.as_slice());
                if !rest.is_empty() || !one_form {
                    return Err(Error::InvalidInvitation);
                }
                invitation
            }
            Some(PAIRING_VERSION_WITH_RELAY) => {
                // Its tokens are wiped when it drops, on every path.
                let (mut wide, rest): (InvitationBodyWithRelay, _) =
                    postcard::take_from_bytes(&bytes).map_err(|_| Error::InvalidInvitation)?;
                let one_form = postcard::to_allocvec(&wide)
                    .map(Zeroizing::new)
                    .is_ok_and(|again| again.as_slice() == bytes.as_slice());
                if !rest.is_empty() || !one_form {
                    return Err(Error::InvalidInvitation);
                }
                let relay = RelayCode::new(&wide.relay_address, wide.relay_pin, wide.relay_token)
                    .map_err(|_| Error::InvalidInvitation)?;
                let body = InvitationBody {
                    version: PAIRING_VERSION,
                    vault_id: wide.vault_id,
                    inviter_device_id: wide.inviter_device_id,
                    inviter_public_key: wide.inviter_public_key,
                    inviter_transport_pin: wide.inviter_transport_pin,
                    addresses: std::mem::take(&mut wide.addresses),
                    token: wide.token,
                    expires_at: wide.expires_at,
                };
                Self {
                    body,
                    relay: Some(relay),
                }
            }
            Some(_) => return Err(Error::UnsupportedVersion),
            None => return Err(Error::InvalidInvitation),
        };
        if !valid_addresses(&invitation.body.addresses) {
            return Err(Error::InvalidInvitation);
        }
        Ok(invitation)
    }

    /// The relay of the vault, when the inviter named it for a joiner away
    /// from its networks.
    pub fn relay(&self) -> Option<&RelayCode> {
        self.relay.as_ref()
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

/// Version 1 join request (retained only for decoding frozen v1 fixtures;
/// live pairing uses [`JoinCommit`] under protocol version 2).
#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    version: u8,
    vault_id: [u8; 32],
    token: [u8; 32],
    joiner_device_id: [u8; 16],
    joiner_public_key: [u8; 32],
    joiner_hpke_key: [u8; 32],
    /// SHA-256 of the joiner's TLS certificate.
    joiner_transport_pin: [u8; 32],
    /// Joiner's pairing signature over the v1 transcript.
    signature: Vec<u8>,
}

impl Drop for JoinRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl std::fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinRequest")
            .field("joiner_device_id", &self.joiner_device_id)
            .finish_non_exhaustive()
    }
}

/// Flight 1 of pairing wire v2: sent by the joiner before seeing the
/// inviter's nonce, committing to its own secret nonce and to the relay
/// carried by the invitation.
#[derive(Serialize, Deserialize)]
pub struct JoinCommit {
    version: u8,
    vault_id: [u8; 32],
    token: [u8; 32],
    joiner_device_id: [u8; 16],
    joiner_public_key: [u8; 32],
    joiner_hpke_key: [u8; 32],
    /// SHA-256 of the joiner's TLS certificate. The inviter checks it
    /// against the certificate the connection presented.
    joiner_transport_pin: [u8; 32],
    /// `SHA-256("osm-pairing-commit-v2\0" || joiner_nonce)`.
    joiner_commit: [u8; 32],
    /// Commitment to the relay carried by the invitation (or its absence).
    relay_binding: [u8; 32],
    /// Joiner's pairing signature over `commit_message(&pre_transcript)`.
    signature: Vec<u8>,
}

impl Drop for JoinCommit {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl JoinCommit {
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn joiner_transport_pin(&self) -> [u8; 32] {
        self.joiner_transport_pin
    }

    #[cfg(test)]
    pub(crate) fn tamper_signature(&mut self) {
        self.signature[0] ^= 1;
    }

    #[cfg(test)]
    pub(crate) fn tamper_relay_binding(&mut self) {
        self.relay_binding[0] ^= 1;
    }
}

impl std::fmt::Debug for JoinCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinCommit")
            .field("joiner_device_id", &self.joiner_device_id)
            .finish_non_exhaustive()
    }
}

/// Flight 2 of pairing wire v2: sent by the inviter after verifying
/// [`JoinCommit`], supplying its fresh nonce and the intended `voting` role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinChallenge {
    version: u8,
    inviter_nonce: [u8; 32],
    voting: bool,
}

impl JoinChallenge {
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn voting(&self) -> Voting {
        if self.voting {
            Voting::Votes
        } else {
            Voting::WithoutVote
        }
    }
}

/// Flight 3 of pairing wire v2: the joiner reveals the nonce committed in
/// [`JoinCommit::joiner_commit`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinReveal {
    version: u8,
    joiner_nonce: [u8; 32],
}

impl JoinReveal {
    pub fn version(&self) -> u8 {
        self.version
    }

    #[cfg(test)]
    pub(crate) fn tamper_nonce(&mut self) {
        self.joiner_nonce[0] ^= 1;
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

    #[cfg(test)]
    pub(crate) fn tamper_members(&mut self) {
        self.members.pop();
    }

    /// The enrollment proposal, for cancelling it if the joiner never
    /// appears.
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
}

/// A verified [`JoinCommit`] waiting for the joiner's [`JoinReveal`].
pub struct VerifiedCommit {
    commit: JoinCommit,
    pre_transcript: [u8; 32],
    inviter_nonce: [u8; 32],
    voting: Voting,
}

impl VerifiedCommit {
    /// Checks the joiner's revealed nonce against its earlier commitment and
    /// derives the final transcript and short code.
    pub fn complete(self, reveal: JoinReveal) -> Result<JoinReview> {
        if reveal.version != PAIRING_WIRE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if !same_bytes(
            &commit_nonce(&reveal.joiner_nonce),
            &self.commit.joiner_commit,
        ) {
            return Err(Error::ProtocolViolation);
        }
        let transcript = transcript_v2(
            &self.pre_transcript,
            &self.inviter_nonce,
            &reveal.joiner_nonce,
            self.voting,
        );
        Ok(JoinReview {
            commit: self.commit,
            transcript,
            voting: self.voting,
        })
    }
}

/// A verified join handshake awaiting the owner's decision on the inviter.
pub struct JoinReview {
    commit: JoinCommit,
    transcript: [u8; 32],
    voting: Voting,
}

impl JoinReview {
    /// The short code to compare with the joiner's screen.
    pub fn sas(&self) -> String {
        short_code_v2(&self.transcript)
    }

    pub fn joiner_device_id(&self) -> [u8; 16] {
        self.commit.joiner_device_id
    }

    pub fn voting(&self) -> Voting {
        self.voting
    }

    /// The joiner as committed membership will record it.
    pub fn joiner_node(&self) -> DeviceNode {
        DeviceNode {
            public_key: self.commit.joiner_public_key,
            transport_pin: self.commit.joiner_transport_pin,
            recipient_key: self.commit.joiner_hpke_key,
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
        relay: None,
    })
}

/// As [`invite`], for a joiner that may be away from the inviter's
/// networks: the invitation also carries `relay`, the vault's, by which the
/// joiner reaches the inviter. It holds the relay's token, so it is shown
/// only when the owner asks for it.
pub fn invite_through_relay(
    vault: &Vault,
    invitations: &mut InvitationStore,
    peers: &mut PeerStore,
    mut addresses: Vec<String>,
    relay: &RelayCode,
    now: u64,
    ttl_secs: u64,
) -> Result<Invitation> {
    let mut invitation = invite(vault, invitations, peers, addresses.clone(), now, ttl_secs)?;
    invitation.relay = Some(relay.clone());
    // The relay takes room the addresses had: the later addresses, which
    // are the less likely to be the joiner's way, are left out until the code
    // fits what can be scanned and pasted.
    while invitation.encode().is_err() {
        if addresses.pop().is_none() {
            return Err(Error::InvalidInvitation);
        }
        invitation.body.addresses = addresses.clone();
    }
    Ok(invitation)
}

/// Validates Flight 1 ([`JoinCommit`]) without consuming the invitation,
/// checking the token, relay commitment, and joiner signature, and creates
/// Flight 2 ([`JoinChallenge`]) with a fresh inviter nonce and the intended
/// `voting` role.
pub fn review_commit(
    vault: &Vault,
    invitations: &InvitationStore,
    peers: &mut PeerStore,
    commit: JoinCommit,
    voting: Voting,
    relay: Option<&RelayCode>,
    now: u64,
) -> Result<(VerifiedCommit, JoinChallenge)> {
    let inviter_pin = peers.transport_identity()?.pin();
    if commit.version != PAIRING_WIRE_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if commit.vault_id != vault.vault_id() {
        return Err(Error::VaultMismatch);
    }
    let token = InvitationToken::from_bytes(commit.token);
    if invitations.check(&token, now)? != VaultId(vault.vault_id()) {
        return Err(Error::VaultMismatch);
    }
    if !same_bytes(&commit.relay_binding, &relay_binding(relay)) {
        return Err(Error::ProtocolViolation);
    }
    let (inviter_id, inviter_key) = own_identity(vault)?;
    let pre_transcript = pre_transcript_v2(
        &Inviter {
            vault_id: &commit.vault_id,
            device_id: &inviter_id,
            public_key: &inviter_key,
            transport_pin: &inviter_pin,
            token: &commit.token,
        },
        &commit,
    );
    verify_pairing_signature(
        &commit.joiner_public_key,
        &commit_message(&pre_transcript),
        &commit.signature,
    )
    .map_err(|_| Error::InvalidSignature)?;
    let inviter_nonce = random_nonce()?;
    let challenge = JoinChallenge {
        version: PAIRING_WIRE_VERSION,
        inviter_nonce,
        voting: voting == Voting::Votes,
    };
    Ok((
        VerifiedCommit {
            commit,
            pre_transcript,
            inviter_nonce,
            voting,
        },
        challenge,
    ))
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
/// this device included (`MemberEndpoint::roster`), `voting` must match the
/// role committed in the handshake, and `listen_port` is where this device
/// accepts member connections, if it listens.
pub fn approve_enrollment(
    vault: &Vault,
    invitations: &mut InvitationStore,
    review: JoinReview,
    members: Vec<MemberContact>,
    voting: Voting,
    listen_port: Option<u16>,
    now: u64,
) -> Result<(SignedRequest, EnrollmentGrant)> {
    if voting != review.voting {
        return Err(Error::ProtocolViolation);
    }
    if !valid_contacts(&members) {
        return Err(Error::InvalidAddress);
    }
    let request = control::enrollment_request(
        vault,
        review.commit.joiner_device_id,
        review.joiner_node(),
        voting,
    )?;
    let mut grant = EnrollmentGrant {
        version: PAIRING_WIRE_VERSION,
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
        &InvitationToken::from_bytes(review.commit.token),
        DeviceId(review.commit.joiner_public_key),
        now,
    )?;
    Ok((request, grant))
}

/// The joining device before receiving the inviter's [`JoinChallenge`].
pub struct PendingJoiner {
    invitation: Invitation,
    device_id: [u8; 16],
    public_key: [u8; 32],
    recipient_key: [u8; 32],
    pending: Option<(PendingDevice, HpkeKeyPair)>,
    transport_pin: [u8; 32],
    pre_transcript: [u8; 32],
    joiner_nonce: Zeroizing<[u8; 32]>,
}

impl PendingJoiner {
    pub(crate) fn inviter_transport_pin(&self) -> [u8; 32] {
        self.invitation.body.inviter_transport_pin
    }

    pub(crate) fn inviter_addresses(&self) -> &[String] {
        &self.invitation.body.addresses
    }

    /// The relay the invitation named, if it named one.
    pub fn invitation_relay(&self) -> Option<&RelayCode> {
        self.invitation.relay.as_ref()
    }

    /// Accepts Flight 2 ([`JoinChallenge`]), derives the joint transcript and
    /// SAS, and returns the live [`Joiner`] alongside Flight 3 ([`JoinReveal`]).
    pub fn accept_challenge(self, challenge: &JoinChallenge) -> Result<(Joiner, JoinReveal)> {
        if challenge.version != PAIRING_WIRE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let voting = challenge.voting();
        let transcript = transcript_v2(
            &self.pre_transcript,
            &challenge.inviter_nonce,
            &self.joiner_nonce,
            voting,
        );
        let reveal = JoinReveal {
            version: PAIRING_WIRE_VERSION,
            joiner_nonce: *self.joiner_nonce,
        };
        Ok((
            Joiner {
                invitation: self.invitation,
                device_id: self.device_id,
                public_key: self.public_key,
                recipient_key: self.recipient_key,
                pending: self.pending,
                transport_pin: self.transport_pin,
                transcript,
                voting,
            },
            reveal,
        ))
    }
}

/// The joining device's side of pairing, after completing commit-before-reveal.
pub struct Joiner {
    invitation: Invitation,
    device_id: [u8; 16],
    public_key: [u8; 32],
    /// The device's long-lived HPKE recipient key.
    recipient_key: [u8; 32],
    /// The identity of a device that has no vault yet, with the recipient
    /// key pair derived from the secret its vault will keep. `None` for a
    /// device joining with the vault it already has.
    pending: Option<(PendingDevice, HpkeKeyPair)>,
    transport_pin: [u8; 32],
    transcript: [u8; 32],
    voting: Voting,
}

impl Joiner {
    /// Creates a new device's identity and Flight 1 ([`JoinCommit`]) to send.
    /// `transport_pin` is this device's TLS certificate hash.
    pub fn start(
        invitation: Invitation,
        transport_pin: [u8; 32],
        now: u64,
    ) -> Result<(PendingJoiner, JoinCommit)> {
        let device = PendingDevice::generate();
        let hpke = HpkeKeyPair::from_secret(&device.recipient_secret());
        let (device_id, public_key) = (device.device_id(), device.public_key());
        let recipient_key = hpke.public().as_bytes();
        let signer = |message: &[u8]| Ok(device.sign_pairing(message));
        let mut started = Self::begin(
            invitation,
            device_id,
            public_key,
            recipient_key,
            transport_pin,
            now,
            signer,
        )?;
        started.0.pending = Some((device, hpke));
        Ok(started)
    }

    /// Creates Flight 1 ([`JoinCommit`]) for a device that already holds a copy
    /// of the invitation's vault and joins its control plane under the identity
    /// it has. The vault must be unlocked.
    pub fn start_with_vault(
        invitation: Invitation,
        vault: &Vault,
        transport_pin: [u8; 32],
        now: u64,
    ) -> Result<(PendingJoiner, JoinCommit)> {
        if invitation.body.vault_id != vault.vault_id() {
            return Err(Error::VaultMismatch);
        }
        let (device_id, public_key) = own_identity(vault)?;
        let recipient = HpkeKeyPair::from_secret(&*vault.recipient_secret()?);
        Self::begin(
            invitation,
            device_id,
            public_key,
            recipient.public().as_bytes(),
            transport_pin,
            now,
            |message| Ok(vault.sign_pairing(message)?),
        )
    }

    fn begin(
        invitation: Invitation,
        device_id: [u8; 16],
        public_key: [u8; 32],
        recipient_key: [u8; 32],
        transport_pin: [u8; 32],
        now: u64,
        sign: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
    ) -> Result<(PendingJoiner, JoinCommit)> {
        if now >= invitation.body.expires_at {
            return Err(Error::InvitationExpired);
        }
        let joiner_nonce = Zeroizing::new(random_nonce()?);
        let joiner_commit = commit_nonce(&joiner_nonce);
        let relay_binding = relay_binding(invitation.relay.as_ref());
        let body = &invitation.body;
        let mut commit = JoinCommit {
            version: PAIRING_WIRE_VERSION,
            vault_id: body.vault_id,
            token: body.token,
            joiner_device_id: device_id,
            joiner_public_key: public_key,
            joiner_hpke_key: recipient_key,
            joiner_transport_pin: transport_pin,
            joiner_commit,
            relay_binding,
            signature: Vec::new(),
        };
        let pre_transcript = pre_transcript_v2(
            &Inviter {
                vault_id: &body.vault_id,
                device_id: &body.inviter_device_id,
                public_key: &body.inviter_public_key,
                transport_pin: &body.inviter_transport_pin,
                token: &body.token,
            },
            &commit,
        );
        commit.signature = sign(&commit_message(&pre_transcript))?.to_vec();
        Ok((
            PendingJoiner {
                invitation,
                device_id,
                public_key,
                recipient_key,
                pending: None,
                transport_pin,
                pre_transcript,
                joiner_nonce,
            },
            commit,
        ))
    }

    /// Whether this device joins with the vault it already has.
    pub fn has_vault(&self) -> bool {
        self.pending.is_none()
    }

    /// Whether the inviter committed to enrolling this device as a voter.
    pub fn voting(&self) -> Voting {
        self.voting
    }

    /// The addresses the invitation named for the inviter, each with the
    /// port it accepts its vault's members on, from its grant.
    pub(crate) fn inviter_member_addresses(&self, grant: &EnrollmentGrant) -> Vec<String> {
        let body = &self.invitation.body;
        body.addresses
            .iter()
            .filter_map(|address| {
                grant
                    .inviter_port
                    .and_then(|port| sync_address(Some(address), Some(port)))
            })
            .collect()
    }

    pub(crate) fn inviter_device_id(&self) -> [u8; 16] {
        self.invitation.body.inviter_device_id
    }

    /// The relay the invitation named, if it named one.
    pub fn invitation_relay(&self) -> Option<&RelayCode> {
        self.invitation.relay.as_ref()
    }

    /// This device's ID in the control plane. Start its control-plane node
    /// with it (and [`Joiner::vault_id`]) before the owner confirms, so the
    /// leader can bring it up to date as a learner.
    pub fn control_device(&self) -> osm_vault_membership::DeviceId {
        device_id_from_bytes(self.device_id)
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.invitation.body.vault_id
    }

    /// Whether committed control state lists this device as an enrolled
    /// member holding every epoch key, so [`Joiner::finish_enrollment`] can
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
    /// pairing under wire version 2.
    fn verify_grant(&self, grant: &EnrollmentGrant) -> Result<()> {
        let body = &self.invitation.body;
        if grant.version != PAIRING_WIRE_VERSION {
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

    /// Checks the grant, the owner's confirmation, and that committed state
    /// records this device as an enrolled member with the keys, voting role,
    /// and certificate agreed in the handshake.
    fn check_enrolled(
        &self,
        grant: &EnrollmentGrant,
        owner_confirmed: bool,
        state: &ControlState,
    ) -> Result<()> {
        if !owner_confirmed {
            return Err(Error::NotConfirmed);
        }
        self.verify_grant(grant)?;
        if state.vault_id != self.invitation.body.vault_id {
            return Err(Error::VaultMismatch);
        }
        if !self.enrolled(state) {
            return Err(Error::EnrollmentPending);
        }
        let me = self.control_device();
        let recorded = state.node(me).ok_or(Error::EnrollmentPending)?;
        if recorded.public_key != self.public_key
            || recorded.recipient_key != self.recipient_key
            || recorded.transport_pin != self.transport_pin
            || state.authors.get(&me) != Some(&self.public_key)
            || state.votes(me) != (self.voting == Voting::Votes)
        {
            return Err(Error::ProtocolViolation);
        }
        Ok(())
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
        self.check_enrolled(grant, owner_confirmed, state)?;
        // A device that joins with its own vault finishes in place.
        let (device, hpke) = self.pending.ok_or(Error::ProtocolViolation)?;
        let vault_id = self.invitation.body.vault_id;
        let me = device_id_from_bytes(self.device_id);
        let sealed = state.envelopes.get(&me).ok_or(Error::EnrollmentPending)?;
        let epoch_keys = (1..=state.epoch)
            .map(|epoch| {
                let envelope = sealed.get(&epoch).ok_or(Error::EnrollmentPending)?;
                let key = control::open(&vault_id, epoch, self.public_key, &hpke, envelope)?;
                if state.epoch_checks.get(&epoch) != Some(&epoch_key_check(&vault_id, epoch, &key))
                {
                    return Err(Error::EpochKeyMismatch);
                }
                Ok((epoch, key))
            })
            .collect::<Result<Vec<_>>>()?;
        let material = EnrollmentMaterial {
            vault_id,
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
        Ok(Vault::join(path, password, device, material)?)
    }

    /// Finishes for a device that joined with the vault it already has
    /// ([`Joiner::start_with_vault`]): verifies the grant and brings
    /// `vault`, which must be that vault, unlocked, in line with committed
    /// control state. Its epoch keys are checked against the committed
    /// checks; nothing it holds is replaced. Fails with `EnrollmentPending`
    /// until [`Joiner::enrolled`] holds.
    pub fn finish_in_place(
        self,
        grant: &EnrollmentGrant,
        owner_confirmed: bool,
        state: &ControlState,
        vault: &mut Vault,
    ) -> Result<Reconciled> {
        self.check_enrolled(grant, owner_confirmed, state)?;
        if self.pending.is_some()
            || vault.device_id() != Some(self.device_id)
            || vault.vault_id() != self.invitation.body.vault_id
        {
            return Err(Error::ProtocolViolation);
        }
        control::reconcile(vault, state)
    }

    /// The short code to compare with the inviter's screen.
    pub fn sas(&self) -> String {
        short_code_v2(&self.transcript)
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
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

fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Transport("no randomness"))?;
    Ok(nonce)
}

fn same_bytes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn commit_nonce(joiner_nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"osm-pairing-commit-v2\0")
        .chain_update(joiner_nonce)
        .finalize()
        .into()
}

fn relay_binding(relay: Option<&RelayCode>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-pairing-relay-v2\0");
    match relay {
        None => hasher.update([0]),
        Some(code) => {
            hasher.update([1]);
            let address = code.address().as_bytes();
            hasher.update((address.len() as u64).to_be_bytes());
            hasher.update(address);
            hasher.update(code.pin());
            hasher.update(*code.token());
        }
    }
    hasher.finalize().into()
}

/// The inviter's half of the transcript, from the invitation.
struct Inviter<'a> {
    vault_id: &'a [u8; 32],
    device_id: &'a [u8; 16],
    public_key: &'a [u8; 32],
    transport_pin: &'a [u8; 32],
    token: &'a [u8; 32],
}

/// Version 1 transcript hash (retained only to verify frozen v1 fixtures).
#[cfg(test)]
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

/// Flight 1 pre-transcript binding both identities, the invitation token, the
/// joiner's nonce commitment, and the invitation's relay.
fn pre_transcript_v2(inviter: &Inviter<'_>, commit: &JoinCommit) -> [u8; 32] {
    let token_digest = Sha256::new()
        .chain_update(b"osm-pairing-token-v2\0")
        .chain_update(inviter.token)
        .finalize();
    Sha256::new()
        .chain_update(b"osm-pairing-pre-transcript-v2\0")
        .chain_update(inviter.vault_id)
        .chain_update(inviter.device_id)
        .chain_update(inviter.public_key)
        .chain_update(inviter.transport_pin)
        .chain_update(token_digest)
        .chain_update(commit.joiner_device_id)
        .chain_update(commit.joiner_public_key)
        .chain_update(commit.joiner_hpke_key)
        .chain_update(commit.joiner_transport_pin)
        .chain_update(commit.joiner_commit)
        .chain_update(commit.relay_binding)
        .finalize()
        .into()
}

/// Final pairing wire v2 transcript binding both nonces and the joiner's
/// `voting` role after commit-before-reveal.
fn transcript_v2(
    pre_transcript: &[u8; 32],
    inviter_nonce: &[u8; 32],
    joiner_nonce: &[u8; 32],
    voting: Voting,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"osm-pairing-transcript-v2\0")
        .chain_update(pre_transcript)
        .chain_update(inviter_nonce)
        .chain_update(joiner_nonce)
        .chain_update([u8::from(voting == Voting::Votes)])
        .finalize()
        .into()
}

/// The inviter's member address: its pairing host with the port from the
/// signed grant.
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

#[cfg(test)]
fn request_message(transcript: &[u8; 32]) -> Vec<u8> {
    let mut message = b"join-request\0".to_vec();
    message.extend_from_slice(transcript);
    message
}

fn commit_message(pre_transcript: &[u8; 32]) -> Vec<u8> {
    let mut message = b"join-commit-v2\0".to_vec();
    message.extend_from_slice(pre_transcript);
    message
}

/// Six decimal digits (v1 frozen fixture).
#[cfg(test)]
fn short_code(transcript: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"osm-pairing-sas-v1\0")
        .chain_update(transcript)
        .finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", value / 1000, value % 1000)
}

/// Six decimal digits derived from the wire v2 commit-before-reveal transcript.
fn short_code_v2(transcript: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"osm-pairing-sas-v2\0")
        .chain_update(transcript)
        .finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", value / 1000, value % 1000)
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod fixtures;
