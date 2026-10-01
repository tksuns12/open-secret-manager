use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A Raft node ID is the device's 16-byte ID read as a big-endian integer,
/// so a Raft identity is exactly a device identity.
pub type DeviceId = u128;

pub fn device_id_from_bytes(bytes: [u8; 16]) -> DeviceId {
    u128::from_be_bytes(bytes)
}

pub fn device_id_to_bytes(device: DeviceId) -> [u8; 16] {
    device.to_be_bytes()
}

/// What committed membership records about each device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceNode {
    /// Ed25519 key that signs this device's revisions and control requests.
    pub public_key: [u8; 32],
    /// SHA-256 of the device's TLS certificate.
    pub transport_pin: [u8; 32],
    /// HPKE (X25519) public key that epoch keys are sealed to.
    pub recipient_key: [u8; 32],
}

/// The next epoch key, introduced by a removal and sealed to every device
/// that remains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    /// Exactly one after the current epoch.
    pub epoch: u64,
    /// The new key's check (see `osm_vault_core::epoch_key_check`).
    pub check: [u8; 32],
    /// One epoch-key envelope per remaining voter.
    pub envelopes: Vec<(DeviceId, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipChange {
    /// Add a device as a voter, after it has caught up as a learner. It
    /// receives epoch keys only once it is a voter, through
    /// [`ControlRequest::GrantKeys`].
    Enroll { device: DeviceId, node: DeviceNode },
    /// Remove a voter. The rotation's epoch becomes current when the
    /// removal completes, so the removed device never receives it.
    Remove {
        device: DeviceId,
        rotation: Rotation,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Founds the vault's control plane: its current epoch, the check of
    /// every epoch key so far (`checks[i]` is epoch `i + 1`), and every
    /// device whose revisions the vault accepts. Accepted once, from a
    /// voter, which holds all those keys.
    Genesis {
        epoch: u64,
        checks: Vec<[u8; 32]>,
        authors: Vec<(DeviceId, [u8; 32])>,
    },
    /// Starts a membership change. At most one may be pending.
    ProposeChange(MembershipChange),
    /// Abandons a pending enrollment, for example because the new device
    /// never came online. It never received epoch keys.
    CancelEnrollment { request_id: [u8; 16] },
    /// Delivers epoch keys to a voter that lacks them: one epoch-key
    /// envelope per epoch, sealed to the voter's recipient key.
    GrantKeys {
        device: DeviceId,
        envelopes: Vec<Vec<u8>>,
    },
}

/// A control-plane command with its authorization context. The state
/// machine verifies the signature against the requester's key in the
/// committed membership at the point the command is applied, so every node
/// reaches the same verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequest {
    /// Stable ID: resubmitting the same request is recognized.
    pub request_id: [u8; 16],
    pub requester: DeviceId,
    pub request: ControlRequest,
    pub signature: Vec<u8>,
}

/// The application payload of a log entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlEntry {
    Request(SignedRequest),
    /// The leader's record that the pending change `request_id` has taken
    /// effect. It carries no authority of its own: the state machine accepts
    /// it only when the committed membership is uniform and equals the
    /// change's target, which every node can check. It is unsigned so that a
    /// leader whose vault is locked can still finish a change.
    Complete {
        request_id: [u8; 16],
    },
}

/// Every control signature covers this prefix and then the message, so it
/// can never pass as a revision or pairing signature by the same key. The
/// vault core prepends the same bytes (`CONTROL_SIGNATURE_DOMAIN`).
pub const SIGNATURE_DOMAIN: &[u8] = b"osm-control-signature-v1\0";
const REQUEST_DOMAIN: &[u8] = b"osm-control-request-v2\0";

impl SignedRequest {
    pub fn sign(
        vault_id: &[u8; 32],
        request_id: [u8; 16],
        requester: DeviceId,
        request: ControlRequest,
        signer: &dyn RequestSigner,
    ) -> Self {
        Self::sign_with(vault_id, request_id, requester, request, |message| {
            Ok::<_, std::convert::Infallible>(signer.sign(message))
        })
        .unwrap_or_else(|never| match never {})
    }

    /// Signs with `sign`, which must sign [`SIGNATURE_DOMAIN`] followed by
    /// the message it is given.
    pub fn sign_with<E>(
        vault_id: &[u8; 32],
        request_id: [u8; 16],
        requester: DeviceId,
        request: ControlRequest,
        sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
    ) -> Result<Self, E> {
        let mut signed = Self {
            request_id,
            requester,
            request,
            signature: Vec::new(),
        };
        signed.signature = sign(&signed.signed_message(vault_id))?.to_vec();
        Ok(signed)
    }

    /// Canonical bytes covered by the signature, after
    /// [`SIGNATURE_DOMAIN`]. Every field is fixed length, tagged, or
    /// length-prefixed, so no two requests encode the same way, and the
    /// vault ID binds a request to one vault's control plane.
    pub fn signed_message(&self, vault_id: &[u8; 32]) -> Vec<u8> {
        let mut message = REQUEST_DOMAIN.to_vec();
        message.extend_from_slice(vault_id);
        message.extend_from_slice(&self.request_id);
        message.extend_from_slice(&self.requester.to_be_bytes());
        match &self.request {
            ControlRequest::Genesis {
                epoch,
                checks,
                authors,
            } => {
                message.push(1);
                message.extend_from_slice(&epoch.to_be_bytes());
                push_len(&mut message, checks.len());
                for check in checks {
                    message.extend_from_slice(check);
                }
                push_len(&mut message, authors.len());
                for (device, public_key) in authors {
                    message.extend_from_slice(&device.to_be_bytes());
                    message.extend_from_slice(public_key);
                }
            }
            ControlRequest::ProposeChange(MembershipChange::Enroll { device, node }) => {
                message.push(2);
                message.extend_from_slice(&device.to_be_bytes());
                message.extend_from_slice(&node.public_key);
                message.extend_from_slice(&node.transport_pin);
                message.extend_from_slice(&node.recipient_key);
            }
            ControlRequest::ProposeChange(MembershipChange::Remove { device, rotation }) => {
                message.push(3);
                message.extend_from_slice(&device.to_be_bytes());
                message.extend_from_slice(&rotation.epoch.to_be_bytes());
                message.extend_from_slice(&rotation.check);
                push_len(&mut message, rotation.envelopes.len());
                for (recipient, envelope) in &rotation.envelopes {
                    message.extend_from_slice(&recipient.to_be_bytes());
                    push_bytes(&mut message, envelope);
                }
            }
            ControlRequest::CancelEnrollment { request_id } => {
                message.push(4);
                message.extend_from_slice(request_id);
            }
            ControlRequest::GrantKeys { device, envelopes } => {
                message.push(5);
                message.extend_from_slice(&device.to_be_bytes());
                push_len(&mut message, envelopes.len());
                for envelope in envelopes {
                    push_bytes(&mut message, envelope);
                }
            }
        }
        message
    }

    pub(crate) fn verify(&self, vault_id: &[u8; 32], public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let mut signed = SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(&self.signed_message(vault_id));
        key.verify_strict(&signed, &signature).is_ok()
    }
}

fn push_len(message: &mut Vec<u8>, len: usize) {
    message.extend_from_slice(&(len as u64).to_be_bytes());
}

fn push_bytes(message: &mut Vec<u8>, bytes: &[u8]) {
    push_len(message, bytes.len());
    message.extend_from_slice(bytes);
}

/// Signs control requests as one device: [`SIGNATURE_DOMAIN`] followed by
/// the message. In the app the vault signs (`Vault::sign_control`); tests
/// use a plain key.
pub trait RequestSigner {
    fn device(&self) -> DeviceId;
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// A [`RequestSigner`] holding an Ed25519 key directly.
pub struct KeySigner {
    pub device: DeviceId,
    pub key: SigningKey,
}

impl RequestSigner for KeySigner {
    fn device(&self) -> DeviceId {
        self.device
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut signed = SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(message);
        self.key.sign(&signed).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    /// The requester is not a voter in the committed membership.
    Unauthorized,
    BadSignature,
    /// No genesis has been committed yet.
    NotInitialized,
    /// Another membership change is still pending.
    ChangeInProgress,
    /// A completion or cancellation that does not match the pending
    /// change, or a completion that arrives before the change has taken
    /// effect.
    NotPending,
    /// The request does not apply to the current state.
    InvalidChange(String),
}

/// The state machine's verdict on one log entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// A blank or membership entry; nothing to report.
    #[default]
    Recorded,
    Accepted,
    /// The request ID was already applied; this is its earlier verdict.
    AlreadyApplied(Box<Outcome>),
    Rejected(Rejection),
}
