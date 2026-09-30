use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"OSM1";
const VERSION: u8 = 1;
const KIND_REVISION: u8 = 1;
const FLAG_HAS_PARENT: u16 = 1;
const HEADER_LEN: usize = 148;
const SIGNATURE_LEN: usize = 64;
const MIN_FRAME_LEN: usize = HEADER_LEN + SIGNATURE_LEN;

/// An absolute ceiling that a caller cannot raise.
pub const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevisionId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolLimits {
    max_ciphertext_bytes: usize,
}

impl ProtocolLimits {
    pub const DEFAULT_MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

    pub fn new(max_ciphertext_bytes: usize) -> Result<Self> {
        if max_ciphertext_bytes > MAX_CIPHERTEXT_BYTES {
            return Err(Error::FrameTooLarge);
        }
        Ok(Self {
            max_ciphertext_bytes,
        })
    }

    pub fn max_ciphertext_bytes(self) -> usize {
        self.max_ciphertext_bytes
    }

    fn max_frame_bytes(self) -> usize {
        MIN_FRAME_LEN + self.max_ciphertext_bytes
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_ciphertext_bytes: Self::DEFAULT_MAX_CIPHERTEXT_BYTES,
        }
    }
}

/// Metadata from the encrypted vault revision plus its opaque serialized ciphertext.
///
/// The caller should pass the revision identifier produced by `osm-vault-core`.
/// The signature binds every field, including the immutable parent revision.
pub struct WireRevision {
    pub vault_id: VaultId,
    pub revision_id: RevisionId,
    pub parent_revision: Option<RevisionId>,
    pub key_epoch: u64,
    pub ciphertext: Vec<u8>,
}

/// A canonical, signed wire revision.
///
/// It intentionally has no `Debug` implementation, reducing the chance that an opaque
/// ciphertext is copied into diagnostics. Access ciphertext only when passing it to the
/// vault-core apply path after unlock.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRevision {
    vault_id: VaultId,
    sender: DeviceId,
    revision_id: RevisionId,
    parent_revision: Option<RevisionId>,
    key_epoch: u64,
    ciphertext: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl SignedRevision {
    pub fn sign(
        revision: WireRevision,
        signing_key: &SigningKey,
        limits: ProtocolLimits,
    ) -> Result<Self> {
        check_ciphertext_len(revision.ciphertext.len(), limits)?;
        let sender = DeviceId(signing_key.verifying_key().to_bytes());
        let mut signed = Self {
            vault_id: revision.vault_id,
            sender,
            revision_id: revision.revision_id,
            parent_revision: revision.parent_revision,
            key_epoch: revision.key_epoch,
            ciphertext: revision.ciphertext,
            signature: [0; SIGNATURE_LEN],
        };
        let bytes = signed.bytes_before_signature();
        signed.signature = signing_key.sign(&bytes).to_bytes();
        Ok(signed)
    }

    /// Decodes and verifies a frame against the identity pinned by the direct TLS session.
    pub fn verify_and_decode(
        frame: &[u8],
        pinned_sender: DeviceId,
        limits: ProtocolLimits,
    ) -> Result<Self> {
        if frame.len() > limits.max_frame_bytes() {
            return Err(Error::FrameTooLarge);
        }
        if frame.len() < MIN_FRAME_LEN {
            return Err(Error::InvalidFrame);
        }
        if &frame[..4] != MAGIC {
            return Err(Error::InvalidFrame);
        }
        if frame[4] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if frame[5] != KIND_REVISION {
            return Err(Error::InvalidFrame);
        }

        let flags = u16::from_be_bytes(frame[6..8].try_into().expect("fixed range"));
        if flags & !FLAG_HAS_PARENT != 0 {
            return Err(Error::InvalidFrame);
        }
        let vault_id = VaultId(frame[8..40].try_into().expect("fixed range"));
        let sender = DeviceId(frame[40..72].try_into().expect("fixed range"));
        if sender != pinned_sender {
            return Err(Error::SenderIdentityMismatch);
        }
        let revision_id = RevisionId(frame[72..104].try_into().expect("fixed range"));
        let parent_bytes: [u8; 32] = frame[104..136].try_into().expect("fixed range");
        let parent_revision = if flags & FLAG_HAS_PARENT != 0 {
            Some(RevisionId(parent_bytes))
        } else {
            if parent_bytes != [0; 32] {
                return Err(Error::InvalidFrame);
            }
            None
        };
        let key_epoch = u64::from_be_bytes(frame[136..144].try_into().expect("fixed range"));
        let ciphertext_len =
            u32::from_be_bytes(frame[144..148].try_into().expect("fixed range")) as usize;
        check_ciphertext_len(ciphertext_len, limits)?;
        let expected_len = MIN_FRAME_LEN
            .checked_add(ciphertext_len)
            .ok_or(Error::FrameTooLarge)?;
        if frame.len() != expected_len {
            return Err(Error::InvalidFrame);
        }

        let signature_offset = HEADER_LEN + ciphertext_len;
        let signature_bytes: [u8; SIGNATURE_LEN] = frame[signature_offset..]
            .try_into()
            .map_err(|_| Error::InvalidFrame)?;
        let verifying_key =
            VerifyingKey::from_bytes(&sender.0).map_err(|_| Error::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(&frame[..signature_offset], &signature)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(Self {
            vault_id,
            sender,
            revision_id,
            parent_revision,
            key_epoch,
            ciphertext: frame[HEADER_LEN..signature_offset].to_vec(),
            signature: signature_bytes,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes_before_signature();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn message_id(&self) -> MessageId {
        let digest = Sha256::digest(self.to_bytes());
        MessageId(digest.into())
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn sender(&self) -> DeviceId {
        self.sender
    }

    pub fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    pub fn parent_revision(&self) -> Option<RevisionId> {
        self.parent_revision
    }

    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn bytes_before_signature(&self) -> Vec<u8> {
        let flags = if self.parent_revision.is_some() {
            FLAG_HAS_PARENT
        } else {
            0
        };
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(KIND_REVISION);
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&self.vault_id.0);
        bytes.extend_from_slice(&self.sender.0);
        bytes.extend_from_slice(&self.revision_id.0);
        bytes.extend_from_slice(
            &self
                .parent_revision
                .map(|parent| parent.0)
                .unwrap_or([0; 32]),
        );
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
}

fn check_ciphertext_len(len: usize, limits: ProtocolLimits) -> Result<()> {
    if len > limits.max_ciphertext_bytes || len > MAX_CIPHERTEXT_BYTES || len > u32::MAX as usize {
        return Err(Error::FrameTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed() -> SignedRevision {
        SignedRevision::sign(
            WireRevision {
                vault_id: VaultId([1; 32]),
                revision_id: RevisionId([2; 32]),
                parent_revision: Some(RevisionId([3; 32])),
                key_epoch: 7,
                ciphertext: b"opaque encrypted revision".to_vec(),
            },
            &SigningKey::from_bytes(&[9; 32]),
            ProtocolLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_binds_parent_and_sender() {
        let signed = signed();
        let decoded = SignedRevision::verify_and_decode(
            &signed.to_bytes(),
            signed.sender(),
            ProtocolLimits::default(),
        )
        .unwrap();
        assert_eq!(decoded.parent_revision(), Some(RevisionId([3; 32])));
        assert_eq!(decoded.ciphertext(), b"opaque encrypted revision");
    }

    #[test]
    fn rejects_payload_and_identity_tampering() {
        let signed = signed();
        let mut bytes = signed.to_bytes();
        bytes[HEADER_LEN] ^= 1;
        assert!(matches!(
            SignedRevision::verify_and_decode(&bytes, signed.sender(), ProtocolLimits::default()),
            Err(Error::InvalidSignature)
        ));
        assert!(matches!(
            SignedRevision::verify_and_decode(
                &signed.to_bytes(),
                DeviceId([4; 32]),
                ProtocolLimits::default()
            ),
            Err(Error::SenderIdentityMismatch)
        ));
    }

    #[test]
    fn enforces_limits_before_payload_copy() {
        let limits = ProtocolLimits::new(4).unwrap();
        let result = SignedRevision::sign(
            WireRevision {
                vault_id: VaultId([0; 32]),
                revision_id: RevisionId([1; 32]),
                parent_revision: None,
                key_epoch: 1,
                ciphertext: vec![0; 5],
            },
            &SigningKey::from_bytes(&[7; 32]),
            limits,
        );
        assert!(matches!(result, Err(Error::FrameTooLarge)));
    }
}
