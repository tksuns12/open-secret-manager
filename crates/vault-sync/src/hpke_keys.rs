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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HpkePublicKey([u8; KEY_LEN]);

impl HpkePublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self> {
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
        let (private, public) = Kem::derive_keypair(ikm.as_ref());
        let private_bytes: [u8; KEY_LEN] = private
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 private key size");
        let public_bytes: [u8; KEY_LEN] = public
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 public key size");
        Ok(Self {
            private: HpkePrivateKey(private_bytes),
            public: HpkePublicKey(public_bytes),
        })
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
        let recipient = DeviceId(bytes[44..76].try_into().expect("fixed range"));
        let recipient_key =
            HpkePublicKey::from_bytes(bytes[76..108].try_into().expect("fixed range"))?;
        let encapsulated_key = bytes[108..140].try_into().expect("fixed range");
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
    if envelope.vault_id != expected_vault
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
    let mut opened = context
        .open(&envelope.ciphertext, &aad)
        .map_err(|_| Error::Hpke)?;
    let key: [u8; KEY_LEN] = opened.as_slice().try_into().map_err(|_| Error::Hpke)?;
    opened.zeroize();
    Ok(Zeroizing::new(key))
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
}
