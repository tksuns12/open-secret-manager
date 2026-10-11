//! The system's keystore, which seals this device's TLS key so that the
//! peer store's file alone does not give it away.
//!
//! The key is still used here, in this process: rustls signs with it, and
//! the keystores of the phones the apps support cannot sign with Ed25519.
//! What the keystore adds is that a copy of the device's files, in a backup
//! or on another computer, holds the key only sealed, under a key that
//! stays in the system that sealed it. A sealed key is opened without the
//! vault's password, so a locked device can still receive ciphertext.

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;
use zeroize::Zeroizing;

/// Seals and opens this device's TLS key with a key the system keeps.
/// Each platform's app gives its own: the macOS Keychain or the Linux
/// Secret Service on the desktop, the Android Keystore, the iOS Keychain.
pub trait Keystore: Send + Sync {
    /// Seals `key`. What comes back is stored as it is and later given to
    /// [`Keystore::open`]; it must name whatever the keystore needs to
    /// find its own key again.
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>, KeystoreError>;

    /// Opens what [`Keystore::seal`] returned.
    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError>;
}

/// Why the keystore could not seal or open a key. None of these carry the
/// key or what it was sealed into.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum KeystoreError {
    /// This system has no keystore, as on a Linux computer without a
    /// Secret Service. A key is then kept unsealed in the peer store.
    #[error("this system has no keystore")]
    Absent,
    /// The keystore is there but did not do it now: locked, refused, or
    /// not answering. Trying again later may work.
    #[error("the system's keystore did not answer")]
    Unavailable,
    /// The keystore answered that the key a TLS key was sealed with is not
    /// there: removed, or these files were copied from another system. The
    /// TLS key cannot be had again, so this device has to be removed from
    /// the vault and joined again.
    #[error("this system's keystore no longer holds this device's network key: remove this device from the vault on another device, then join again")]
    Lost,
}

/// A keystore for a system that has none: nothing is sealed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoKeystore;

impl Keystore for NoKeystore {
    fn seal(&self, _key: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        Err(KeystoreError::Absent)
    }

    fn open(&self, _sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        Err(KeystoreError::Absent)
    }
}

/// A keystore held in memory, for tests: what it seals is an entry name,
/// and the key itself stays in the map. It can be told to stop answering
/// or to lose everything it holds.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct MemoryKeystore {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    entries: HashMap<Vec<u8>, Zeroizing<Vec<u8>>>,
    next: u64,
    unavailable: bool,
}

impl MemoryKeystore {
    /// Makes every later call answer [`KeystoreError::Unavailable`], or
    /// answer again.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.state().unavailable = unavailable;
    }

    /// Forgets every key it holds.
    pub fn lose_everything(&self) {
        self.state().entries.clear();
    }

    /// How many keys it holds.
    pub fn len(&self) -> usize {
        self.state().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Keystore for MemoryKeystore {
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let mut state = self.state();
        if state.unavailable {
            return Err(KeystoreError::Unavailable);
        }
        state.next += 1;
        let name = format!("entry-{}", state.next).into_bytes();
        state
            .entries
            .insert(name.clone(), Zeroizing::new(key.to_vec()));
        Ok(name)
    }

    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        let state = self.state();
        if state.unavailable {
            return Err(KeystoreError::Unavailable);
        }
        state
            .entries
            .get(sealed)
            .cloned()
            .ok_or(KeystoreError::Lost)
    }
}
