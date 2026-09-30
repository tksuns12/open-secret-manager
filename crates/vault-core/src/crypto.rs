use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const SALT_LEN: usize = 16;

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

pub(crate) fn record_aad(
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

pub(crate) fn revision_id(aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> String {
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
