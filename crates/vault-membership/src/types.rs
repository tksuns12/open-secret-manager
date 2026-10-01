use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A Raft node ID is the device's 16-byte ID read as a big-endian integer,
/// so a Raft identity is exactly a device identity.
pub type DeviceId = u128;

pub fn device_id_from_bytes(bytes: [u8; 16]) -> DeviceId {
    u128::from_be_bytes(bytes)
}

/// What committed membership records about each device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceNode {
    /// Ed25519 key that signs this device's revisions and control requests.
    pub public_key: [u8; 32],
    /// SHA-256 of the device's TLS certificate.
    pub transport_pin: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipChange {
    /// Add a device as a voter, after it has caught up as a learner.
    Enroll { device: DeviceId, node: DeviceNode },
    /// Remove a voter.
    Remove { device: DeviceId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Starts a membership change. At most one may be pending.
    ProposeChange(MembershipChange),
    /// Records that the pending change `request_id` has taken effect. The
    /// state machine accepts it only once the committed membership matches
    /// the change's target.
    CompleteChange { request_id: [u8; 16] },
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

const REQUEST_DOMAIN: &[u8] = b"osm-control-request-v1\0";

impl SignedRequest {
    pub fn sign(
        request_id: [u8; 16],
        requester: DeviceId,
        request: ControlRequest,
        signer: &dyn RequestSigner,
    ) -> Self {
        let mut signed = Self {
            request_id,
            requester,
            request,
            signature: Vec::new(),
        };
        signed.signature = signer.sign(&signed.signed_message()).to_vec();
        signed
    }

    /// Canonical bytes covered by the signature. Every field is fixed length
    /// or tagged, so no two requests encode the same way.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut message = REQUEST_DOMAIN.to_vec();
        message.extend_from_slice(&self.request_id);
        message.extend_from_slice(&self.requester.to_be_bytes());
        match &self.request {
            ControlRequest::ProposeChange(MembershipChange::Enroll { device, node }) => {
                message.push(1);
                message.extend_from_slice(&device.to_be_bytes());
                message.extend_from_slice(&node.public_key);
                message.extend_from_slice(&node.transport_pin);
            }
            ControlRequest::ProposeChange(MembershipChange::Remove { device }) => {
                message.push(2);
                message.extend_from_slice(&device.to_be_bytes());
            }
            ControlRequest::CompleteChange { request_id } => {
                message.push(3);
                message.extend_from_slice(request_id);
            }
        }
        message
    }

    pub(crate) fn verify(&self, public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        key.verify_strict(&self.signed_message(), &signature)
            .is_ok()
    }
}

/// Signs control requests as one device. In the app this is backed by the
/// vault's device key; tests use a plain key.
pub trait RequestSigner: Send + Sync + 'static {
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
        self.key.sign(message).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    /// The requester is not a voter in the committed membership.
    Unauthorized,
    BadSignature,
    /// Another membership change is still pending.
    ChangeInProgress,
    /// A completion that does not match the pending change, or arrives
    /// before the change has taken effect.
    NotPending,
    /// The change does not apply to the current membership.
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
