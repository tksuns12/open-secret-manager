use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DeviceId, Error, Result, VaultId};

type Kem = X25519HkdfSha256;
const INFO: &[u8] = b"osm-epoch-key-hpke-v1";
const ENVELOPE_MAGIC: &[u8; 4] = b"OSK1";
const KEY_LEN: usize = 32;
const ENCAPSULATED_KEY_LEN: usize = 32;
const SEALED_EPOCH_KEY_LEN: usize = 48;
const ENCODED_ENVELOPE_LEN: usize =
    4 + 32 + 8 + 32 + KEY_LEN + ENCAPSULATED_KEY_LEN + SEALED_EPOCH_KEY_LEN;

/// Low-order and non-canonical Curve25519 Montgomery u-coordinates (with bit
/// 255 cleared), matching `curve25519-dalek`'s `X25519_LOW_ORDER_POINTS`.
/// Rejecting them prevents enrolling a recipient key that later DoSes HPKE
/// key rotation (`setup_sender` fails with `EncapError`).
const X25519_LOW_ORDER_POINTS: [[u8; KEY_LEN]; 7] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn is_low_order_x25519(bytes: &[u8; KEY_LEN]) -> bool {
    let mut masked = *bytes;
    masked[31] &= 0x7f;
    X25519_LOW_ORDER_POINTS.contains(&masked)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HpkePublicKey([u8; KEY_LEN]);

impl HpkePublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self> {
        if is_low_order_x25519(&bytes) {
            return Err(Error::InvalidPublicKey);
        }
        <Kem as KemTrait>::PublicKey::from_bytes(&bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePrivateKey([u8; KEY_LEN]);

impl HpkePrivateKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self> {
        <Kem as KemTrait>::PrivateKey::from_bytes(&bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self(bytes))
    }

    /// Returns a zeroizing copy suitable for writing to an OS key store.
    pub fn expose_secret(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0)
    }
}

pub struct HpkeKeyPair {
    private: HpkePrivateKey,
    public: HpkePublicKey,
}

impl HpkeKeyPair {
    pub fn generate() -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(ikm.as_mut()).map_err(|_| Error::Randomness)?;
        Ok(Self::from_secret(&ikm))
    }

    /// Derives the key pair from a stored 32-byte secret with the KEM's
    /// `DeriveKeyPair`, so a device can keep one long-lived recipient key
    /// without storing the X25519 key itself.
    pub fn from_secret(secret: &[u8; KEY_LEN]) -> Self {
        let (private, public) = Kem::derive_keypair(secret);
        let mut raw_private = private.to_bytes();
        let private_bytes: [u8; KEY_LEN] = raw_private
            .as_slice()
            .try_into()
            .expect("X25519 private key size");
        raw_private.zeroize();
        let public_bytes: [u8; KEY_LEN] = public
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 public key size");
        Self {
            private: HpkePrivateKey(private_bytes),
            public: HpkePublicKey(public_bytes),
        }
    }

    pub fn public(&self) -> HpkePublicKey {
        self.public
    }

    pub fn private(&self) -> &HpkePrivateKey {
        &self.private
    }
}

/// RFC 9180 ciphertext carrying exactly one 32-byte vault epoch key.
///
/// The authenticated context binds vault, epoch, recipient device identity, and the
/// recipient's HPKE public key. This type intentionally omits `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKeyEnvelope {
    vault_id: VaultId,
    epoch: u64,
    recipient: DeviceId,
    recipient_key: HpkePublicKey,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
    ciphertext: [u8; SEALED_EPOCH_KEY_LEN],
}

impl EpochKeyEnvelope {
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn recipient(&self) -> DeviceId {
        self.recipient
    }

    pub fn recipient_key(&self) -> HpkePublicKey {
        self.recipient_key
    }

    pub fn to_bytes(&self) -> [u8; ENCODED_ENVELOPE_LEN] {
        let mut output = [0u8; ENCODED_ENVELOPE_LEN];
        let mut offset = 0;
        put(&mut output, &mut offset, ENVELOPE_MAGIC);
        put(&mut output, &mut offset, &self.vault_id.0);
        put(&mut output, &mut offset, &self.epoch.to_be_bytes());
        put(&mut output, &mut offset, &self.recipient.0);
        put(&mut output, &mut offset, &self.recipient_key.0);
        put(&mut output, &mut offset, &self.encapsulated_key);
        put(&mut output, &mut offset, &self.ciphertext);
        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCODED_ENVELOPE_LEN || &bytes[..4] != ENVELOPE_MAGIC {
            return Err(Error::InvalidFrame);
        }
        let vault_id = VaultId(bytes[4..36].try_into().expect("fixed range"));
        let epoch = u64::from_be_bytes(bytes[36..44].try_into().expect("fixed range"));
        if epoch == 0 {
            return Err(Error::InvalidFrame);
        }
        let recipient = DeviceId(bytes[44..76].try_into().expect("fixed range"));
        let recipient_key =
            HpkePublicKey::from_bytes(bytes[76..108].try_into().expect("fixed range"))?;
        let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] =
            bytes[108..140].try_into().expect("fixed range");
        if is_low_order_x25519(&encapsulated_key) {
            return Err(Error::InvalidFrame);
        }
        let ciphertext = bytes[140..188].try_into().expect("fixed range");
        Ok(Self {
            vault_id,
            epoch,
            recipient,
            recipient_key,
            encapsulated_key,
            ciphertext,
        })
    }
}

pub fn seal_epoch_key(
    vault_id: VaultId,
    epoch: u64,
    recipient: DeviceId,
    recipient_key: HpkePublicKey,
    epoch_key: &[u8; KEY_LEN],
) -> Result<EpochKeyEnvelope> {
    if epoch == 0 {
        return Err(Error::InvalidRotationEpoch);
    }
    if is_low_order_x25519(&recipient_key.0) {
        return Err(Error::InvalidPublicKey);
    }
    let public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_key.0)
        .map_err(|_| Error::InvalidPublicKey)?;
    let aad = associated_data(vault_id, epoch, recipient, recipient_key);
    let (encapsulated, mut context) =
        setup_sender::<AesGcm256, HkdfSha256, Kem>(&OpModeS::Base, &public, INFO)
            .map_err(|_| Error::Hpke)?;
    let sealed = context.seal(epoch_key, &aad).map_err(|_| Error::Hpke)?;
    Ok(EpochKeyEnvelope {
        vault_id,
        epoch,
        recipient,
        recipient_key,
        encapsulated_key: encapsulated
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Hpke)?,
        ciphertext: sealed.try_into().map_err(|_| Error::Hpke)?,
    })
}

pub fn open_epoch_key(
    envelope: &EpochKeyEnvelope,
    expected_vault: VaultId,
    expected_epoch: u64,
    expected_recipient: DeviceId,
    private_key: &HpkePrivateKey,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if expected_epoch == 0
        || envelope.epoch == 0
        || envelope.vault_id != expected_vault
        || envelope.epoch != expected_epoch
        || envelope.recipient != expected_recipient
    {
        return Err(Error::Hpke);
    }
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(&private_key.0)
        .map_err(|_| Error::InvalidPrivateKey)?;
    let derived_public = Kem::sk_to_pk(&private);
    if derived_public.to_bytes().as_slice() != envelope.recipient_key.0 {
        return Err(Error::InvalidPrivateKey);
    }
    let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.encapsulated_key)
        .map_err(|_| Error::Hpke)?;
    let aad = associated_data(
        envelope.vault_id,
        envelope.epoch,
        envelope.recipient,
        envelope.recipient_key,
    );
    let mut context =
        setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &private, &encapsulated, INFO)
            .map_err(|_| Error::Hpke)?;
    let opened = Zeroizing::new(
        context
            .open(&envelope.ciphertext, &aad)
            .map_err(|_| Error::Hpke)?,
    );
    if opened.len() != KEY_LEN {
        return Err(Error::Hpke);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&opened);
    Ok(key)
}

fn associated_data(
    vault_id: VaultId,
    epoch: u64,
    recipient: DeviceId,
    recipient_key: HpkePublicKey,
) -> [u8; 104] {
    let mut aad = [0u8; 104];
    aad[..32].copy_from_slice(&vault_id.0);
    aad[32..40].copy_from_slice(&epoch.to_be_bytes());
    aad[40..72].copy_from_slice(&recipient.0);
    aad[72..104].copy_from_slice(&recipient_key.0);
    aad
}

fn put<const N: usize>(output: &mut [u8], offset: &mut usize, value: &[u8; N]) {
    output[*offset..*offset + N].copy_from_slice(value);
    *offset += N;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_pair_derived_from_a_secret_is_stable() {
        let first = HpkeKeyPair::from_secret(&[5; 32]);
        let again = HpkeKeyPair::from_secret(&[5; 32]);
        assert_eq!(first.public(), again.public());
        assert_ne!(first.public(), HpkeKeyPair::from_secret(&[6; 32]).public());
        let envelope = seal_epoch_key(
            VaultId([1; 32]),
            1,
            DeviceId([2; 32]),
            first.public(),
            &[3; 32],
        )
        .unwrap();
        let opened = open_epoch_key(
            &envelope,
            VaultId([1; 32]),
            1,
            DeviceId([2; 32]),
            again.private(),
        )
        .unwrap();
        assert_eq!(*opened, [3; 32]);
    }

    #[test]
    fn round_trip_is_bound_to_vault_epoch_and_recipient() {
        let pair = HpkeKeyPair::generate().unwrap();
        let envelope = seal_epoch_key(
            VaultId([1; 32]),
            4,
            DeviceId([2; 32]),
            pair.public(),
            &[7; 32],
        )
        .unwrap();
        let decoded = EpochKeyEnvelope::from_bytes(&envelope.to_bytes()).unwrap();
        let opened = open_epoch_key(
            &decoded,
            VaultId([1; 32]),
            4,
            DeviceId([2; 32]),
            pair.private(),
        )
        .unwrap();
        assert_eq!(*opened, [7; 32]);
        assert!(open_epoch_key(
            &decoded,
            VaultId([1; 32]),
            5,
            DeviceId([2; 32]),
            pair.private()
        )
        .is_err());
    }

    #[test]
    fn tampering_fails_authenticated_open() {
        let pair = HpkeKeyPair::generate().unwrap();
        let envelope = seal_epoch_key(
            VaultId([1; 32]),
            4,
            DeviceId([2; 32]),
            pair.public(),
            &[7; 32],
        )
        .unwrap();
        let mut bytes = envelope.to_bytes();
        bytes[187] ^= 1;
        let tampered = EpochKeyEnvelope::from_bytes(&bytes).unwrap();
        assert!(open_epoch_key(
            &tampered,
            VaultId([1; 32]),
            4,
            DeviceId([2; 32]),
            pair.private()
        )
        .is_err());
    }

    #[test]
    fn low_order_x25519_points_and_epoch_zero_are_refused() {
        for point in X25519_LOW_ORDER_POINTS {
            assert!(matches!(
                HpkePublicKey::from_bytes(point),
                Err(Error::InvalidPublicKey)
            ));
            let mut high_bit = point;
            high_bit[31] |= 0x80;
            assert!(matches!(
                HpkePublicKey::from_bytes(high_bit),
                Err(Error::InvalidPublicKey)
            ));
        }
        let pair = HpkeKeyPair::generate().unwrap();
        assert!(matches!(
            seal_epoch_key(
                VaultId([1; 32]),
                0,
                DeviceId([2; 32]),
                pair.public(),
                &[7; 32]
            ),
            Err(Error::InvalidRotationEpoch)
        ));
        let mut bytes = seal_epoch_key(
            VaultId([1; 32]),
            1,
            DeviceId([2; 32]),
            pair.public(),
            &[7; 32],
        )
        .unwrap()
        .to_bytes();
        bytes[36..44].copy_from_slice(&0_u64.to_be_bytes());
        assert!(matches!(
            EpochKeyEnvelope::from_bytes(&bytes),
            Err(Error::InvalidFrame)
        ));
    }
}
