//! What this computer last saw its vault's file hold, kept in the system's
//! keystore, where an earlier copy of the file put in its place cannot set
//! it back: the number of rows the file never changes or removes
//! ([`Vault::sealed_rows`]). An unlock that finds fewer says that the file
//! was set back, as rows taken out of it are said.
//!
//! What is kept follows the file: it is written after the file's writes
//! commit, so an app stopped between the two leaves only a set back to
//! within that moment unseen, and never says one that did not happen. It
//! only rises, but for the owner confirming what the file holds now. With
//! no keystore (Linux without a Secret Service) nothing is kept, and nothing
//! is checked.

use std::sync::{Arc, Mutex};

use osm_vault_core::Vault;
use tauri::{AppHandle, Manager, Runtime};

use crate::AppState;

/// The service the keystore's entries are kept under: one for each device
/// of a vault this computer has been, its ID in hex the account and the
/// count in decimal the secret.
const SERVICE: &str = "org.opensecretmanager.rows-seen";

/// No keystore answered.
#[derive(Debug, PartialEq, Eq)]
pub struct Unavailable;

/// Where the counts are kept.
pub trait RowsSeen: Send + Sync {
    /// The count kept for `device`, or none.
    fn get(&self, device: &[u8]) -> Result<Option<u64>, Unavailable>;
    fn set(&self, device: &[u8], rows: u64) -> Result<(), Unavailable>;
}

/// The login Keychain on macOS, the Secret Service on Linux, the Credential
/// Manager on Windows (not yet run there).
pub struct KeychainRowsSeen {
    service: &'static str,
}

impl Default for KeychainRowsSeen {
    fn default() -> Self {
        Self { service: SERVICE }
    }
}

impl KeychainRowsSeen {
    fn entry(&self, device: &[u8]) -> Result<keyring::Entry, Unavailable> {
        let account: String = device.iter().map(|byte| format!("{byte:02x}")).collect();
        keyring::Entry::new(self.service, &account).map_err(|_| Unavailable)
    }
}

impl RowsSeen for KeychainRowsSeen {
    fn get(&self, device: &[u8]) -> Result<Option<u64>, Unavailable> {
        match self.entry(device)?.get_password() {
            // What is not a count was not written here, and is written over.
            Ok(text) => Ok(text.parse().ok()),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Unavailable),
        }
    }

    fn set(&self, device: &[u8], rows: u64) -> Result<(), Unavailable> {
        self.entry(device)?
            .set_password(&rows.to_string())
            .map_err(|_| Unavailable)
    }
}

/// The counts in memory, for tests; [`MemoryRowsSeen::set_unavailable`]
/// makes it a keystore that does not answer.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryRowsSeen {
    counts: Mutex<std::collections::HashMap<Vec<u8>, u64>>,
    unavailable: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MemoryRowsSeen {
    pub fn set_unavailable(&self) {
        self.unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn answer(&self) -> Result<(), Unavailable> {
        if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Unavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
impl RowsSeen for MemoryRowsSeen {
    fn get(&self, device: &[u8]) -> Result<Option<u64>, Unavailable> {
        self.answer()?;
        Ok(self.counts.lock().unwrap().get(device).copied())
    }

    fn set(&self, device: &[u8], rows: u64) -> Result<(), Unavailable> {
        self.answer()?;
        self.counts.lock().unwrap().insert(device.to_vec(), rows);
        Ok(())
    }
}

/// The counts, and the last one this process kept, so that the keystore is
/// written only when the file's count rose past it.
pub struct Checkpoint {
    store: Arc<dyn RowsSeen>,
    kept: Mutex<Option<([u8; 16], u64)>>,
}

impl Checkpoint {
    pub fn new(store: Arc<dyn RowsSeen>) -> Self {
        Self {
            store,
            kept: Mutex::new(None),
        }
    }

    fn kept(&self) -> std::sync::MutexGuard<'_, Option<([u8; 16], u64)>> {
        self.kept
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn keep(&self, device: [u8; 16], rows: u64) {
        if self.store.set(&device, rows).is_ok() {
            *self.kept() = Some((device, rows));
        }
    }

    /// At an unlock, before anything received is taken in: whether the
    /// file holds fewer rows than this device last saw, which the vault
    /// then records for the owner to be told. What is kept is then brought
    /// up to the file, never down.
    pub fn check(&self, vault: &mut Vault) -> bool {
        let (Some(device), Ok(rows)) = (vault.device_id(), vault.sealed_rows()) else {
            return false;
        };
        let Ok(seen) = self.store.get(&device) else {
            return false;
        };
        let set_back = seen.is_some_and(|seen| vault.note_set_back(seen).unwrap_or(false));
        let highest = seen.map_or(rows, |seen| seen.max(rows));
        if seen == Some(highest) {
            *self.kept() = Some((device, highest));
        } else {
            self.keep(device, highest);
        }
        set_back
    }

    /// After writes, and before a lock: what is kept rises to what the
    /// file holds.
    pub fn keep_up(&self, vault: &Vault) {
        let (Some(device), Ok(rows)) = (vault.device_id(), vault.sealed_rows()) else {
            return;
        };
        let known = match *self.kept() {
            Some((kept, count)) if kept == device => Some(count),
            _ => match self.store.get(&device) {
                Ok(seen) => seen,
                Err(Unavailable) => return,
            },
        };
        if known.is_none_or(|known| rows > known) {
            self.keep(device, rows);
        }
    }

    /// The owner has seen what the file holds now and takes it as it is:
    /// that is kept, lower than before or not.
    pub fn accept(&self, vault: &Vault) {
        if let (Some(device), Ok(rows)) = (vault.device_id(), vault.sealed_rows()) {
            self.keep(device, rows);
        }
    }
}

/// What is kept rises to what the unlocked vault's file holds.
pub async fn keep_up<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    if let Some(vault) = vault.as_ref().filter(|vault| vault.is_unlocked()) {
        state.rows_seen.keep_up(vault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real keystore of the computer the tests run on, under a service
    /// of the test's own, whose entry is removed after. Not run by default,
    /// like the keystore's own tests (`keystore.rs`).
    #[test]
    #[ignore = "uses this computer's keystore"]
    fn the_system_keystore_keeps_a_count_for_each_device() {
        let store = KeychainRowsSeen {
            service: "org.opensecretmanager.rows-seen.test",
        };
        let device = [0xa5; 16];
        let other = [0x5a; 16];
        assert_eq!(store.get(&device), Ok(None));
        store.set(&device, 41).unwrap();
        assert_eq!(store.get(&device), Ok(Some(41)));
        assert_eq!(store.get(&other), Ok(None));
        store.set(&device, 7).unwrap();
        assert_eq!(store.get(&device), Ok(Some(7)));
        store.entry(&device).unwrap().delete_credential().unwrap();
        assert_eq!(store.get(&device), Ok(None));
    }

    /// Run on Linux with no session bus (scripts/test-linux.sh): nothing is
    /// kept, and an unlock checks nothing.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a Linux system without a Secret Service"]
    fn without_a_secret_service_no_count_is_kept() {
        let store = KeychainRowsSeen::default();
        assert_eq!(store.get(&[1; 16]), Err(Unavailable));
        assert_eq!(store.set(&[1; 16], 1), Err(Unavailable));
    }
}
