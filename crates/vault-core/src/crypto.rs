use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const DEVICE_ID_LEN: usize = 16;
pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const SIGNATURE_LEN: usize = 64;

pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct KdfConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        #[cfg(test)]
        return Self {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        };
        #[cfg(not(test))]
        return Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        };
    }
}

pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut value = [0_u8; N];
    OsRng.fill_bytes(&mut value);
    value
}

pub(crate) fn derive_password_key(
    password: &str,
    salt: &[u8],
    config: KdfConfig,
) -> Result<SecretKey> {
    if password.is_empty() {
        return Err(Error::InvalidCredentials);
    }
    if !(8 * 1024..=256 * 1024).contains(&config.memory_kib)
        || !(1..=10).contains(&config.iterations)
        || !(1..=16).contains(&config.parallelism)
    {
        return Err(Error::Crypto);
    }
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::InvalidCredentials)?;
    Ok(Zeroizing::new(plaintext))
}

pub(crate) fn key_wrap_aad(vault_id: &[u8; 32], method: &[u8]) -> Vec<u8> {
    let mut aad = b"osm-key-wrap-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(method);
    aad
}

/// Wraps a device signing key under the vault master key.
pub(crate) fn device_key_aad(
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut aad = b"osm-device-signing-key-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(public_key);
    aad
}

/// Authenticates a row of the local authorized-author table so that write
/// access to the SQLite file alone cannot add a signer.
pub(crate) fn device_authorization(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; 32]> {
    Ok(
        device_authorization_mac(key, vault_id, device_id, public_key)?
            .finalize()
            .into_bytes()
            .into(),
    )
}

pub(crate) fn verify_device_authorization(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
    tag: &[u8],
) -> Result<()> {
    device_authorization_mac(key, vault_id, device_id, public_key)?
        .verify_slice(tag)
        .map_err(|_| Error::Crypto)
}

fn device_authorization_mac(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<Hmac<Sha256>> {
    // Derive a separate subkey so the master key is never used directly as
    // both an AEAD key and a MAC key.
    let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    derive.update(b"osm-device-authorization-key-v1");
    let subkey = Zeroizing::new(<[u8; 32]>::from(derive.finalize().into_bytes()));
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(subkey.as_ref()).map_err(|_| Error::Crypto)?;
    mac.update(b"osm-device-authorization-v1\0");
    mac.update(vault_id);
    mac.update(device_id);
    mac.update(public_key);
    Ok(mac)
}

/// `parents` are sorted, unique 64-character revision IDs joined into one
/// length-prefixed field. Zero or one parent therefore encodes exactly as the
/// original single-parent layout, so existing signatures and IDs stay valid.
/// Wraps one epoch key under a device's root key.
pub(crate) fn epoch_key_aad(vault_id: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut aad = b"osm-epoch-key-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// A public value that lets a device check a typed recovery key without
/// storing it. The recovery key has 256 bits of entropy, so the check
/// reveals nothing useful about it.
pub(crate) fn recovery_check(recovery: &[u8; KEY_LEN], vault_id: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(recovery_check_mac(recovery, vault_id)?
        .finalize()
        .into_bytes()
        .into())
}

pub(crate) fn verify_recovery_check(
    recovery: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    expected: &[u8; 32],
) -> Result<()> {
    recovery_check_mac(recovery, vault_id)?
        .verify_slice(expected)
        .map_err(|_| Error::InvalidRecoveryKey)
}

fn recovery_check_mac(recovery: &[u8; KEY_LEN], vault_id: &[u8; 32]) -> Result<Hmac<Sha256>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(recovery).map_err(|_| Error::Crypto)?;
    mac.update(b"osm-recovery-check-v1\0");
    mac.update(vault_id);
    Ok(mac)
}

/// Wraps this device's HPKE recipient secret under its root key.
pub(crate) fn recipient_key_aad(vault_id: &[u8; 32], device_id: &[u8; DEVICE_ID_LEN]) -> Vec<u8> {
    let mut aad = b"osm-recipient-key-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(device_id);
    aad
}

/// Marks a device as removed from the vault, keyed by a subkey of this
/// device's root key so only a holder of it can write the mark.
pub(crate) fn device_revocation(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
) -> Result<[u8; 32]> {
    Ok(device_revocation_mac(key, vault_id, device_id)?
        .finalize()
        .into_bytes()
        .into())
}

pub(crate) fn verify_device_revocation(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    tag: &[u8],
) -> Result<()> {
    device_revocation_mac(key, vault_id, device_id)?
        .verify_slice(tag)
        .map_err(|_| Error::Crypto)
}

fn device_revocation_mac(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
) -> Result<Hmac<Sha256>> {
    let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    derive.update(b"osm-device-revocation-key-v1");
    let subkey = Zeroizing::new(<[u8; 32]>::from(derive.finalize().into_bytes()));
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(subkey.as_ref()).map_err(|_| Error::Crypto)?;
    mac.update(b"osm-device-revocation-v1\0");
    mac.update(vault_id);
    mac.update(device_id);
    Ok(mac)
}

/// A public commitment to an epoch key: HMAC-SHA256 keyed by the epoch key
/// over `osm-epoch-key-check-v1`, NUL, the vault ID, and the 64-bit epoch.
/// Committed membership records it, so every member can check that the key
/// it received is the one every other member holds. The key has 256 bits of
/// entropy, so the check reveals nothing useful about it.
pub fn epoch_key_check(vault_id: &[u8; 32], epoch: u64, key: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"osm-epoch-key-check-v1\0");
    mac.update(vault_id);
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Compares two keys without an early exit.
pub(crate) fn keys_equal(left: &[u8; KEY_LEN], right: &[u8; KEY_LEN]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub(crate) fn record_aad(
    vault_id: &[u8; 32],
    item_id: &str,
    parents: &[String],
    key_epoch: u64,
    author_device_id: &[u8; DEVICE_ID_LEN],
    tombstone: bool,
) -> Vec<u8> {
    let mut aad = b"osm-item-revision-v2\0".to_vec();
    aad.extend_from_slice(vault_id);
    push_field(&mut aad, item_id.as_bytes());
    push_field(&mut aad, parents.concat().as_bytes());
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad.extend_from_slice(author_device_id);
    aad.push(u8::from(tombstone));
    aad
}

/// The exact bytes the author device signs with Ed25519.
pub(crate) fn revision_signature_message(aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut message = b"osm-revision-signature-v2\0".to_vec();
    push_field(&mut message, aad);
    push_field(&mut message, nonce);
    push_field(&mut message, ciphertext);
    message
}

pub(crate) fn revision_id(aad: &[u8], nonce: &[u8], ciphertext: &[u8], signature: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-revision-id-v2\0");
    push_field_digest(&mut hasher, aad);
    push_field_digest(&mut hasher, nonce);
    push_field_digest(&mut hasher, ciphertext);
    push_field_digest(&mut hasher, signature);
    hex_encode(&hasher.finalize())
}

/// Format 1 record AAD, kept only to read vaults during migration.
pub(crate) fn legacy_record_aad(
    vault_id: &[u8; 32],
    item_id: &str,
    parent: Option<&str>,
    key_epoch: u64,
    tombstone: bool,
) -> Vec<u8> {
    let mut aad = b"osm-item-revision-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    push_field(&mut aad, item_id.as_bytes());
    push_field(&mut aad, parent.unwrap_or("").as_bytes());
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad.push(u8::from(tombstone));
    aad
}

/// Format 1 revision ID, kept only to validate vaults during migration.
pub(crate) fn legacy_revision_id(aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-revision-id-v1\0");
    push_field_digest(&mut hasher, aad);
    push_field_digest(&mut hasher, nonce);
    push_field_digest(&mut hasher, ciphertext);
    hex_encode(&hasher.finalize())
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn push_field_digest(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub struct RecoveryKey(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKey {
    pub(crate) fn generate() -> Self {
        Self(Zeroizing::new(random_array()))
    }

    pub fn parse(value: &str) -> Result<Self> {
        let encoded = value
            .strip_prefix("OSM-RK1-")
            .ok_or(Error::InvalidRecoveryKey)?;
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        let decoded = Base64UrlUnpadded::decode(encoded, key.as_mut())
            .map_err(|_| Error::InvalidRecoveryKey)?;
        if decoded.len() != KEY_LEN {
            return Err(Error::InvalidRecoveryKey);
        }
        Ok(Self(key))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn from_bytes(key: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(key))
    }
}

impl std::fmt::Display for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OSM-RK1-{}",
            Base64UrlUnpadded::encode_string(self.0.as_ref())
        )
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
