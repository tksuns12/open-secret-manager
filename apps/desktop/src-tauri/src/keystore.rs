//! The system's keystore on the desktop, which seals this device's TLS key
//! (see `osm_vault_peer::Keystore`): the login Keychain on macOS, the
//! Secret Service (GNOME Keyring, KWallet) on Linux, the Credential Manager
//! on Windows (not yet run there).
//!
//! Each sealing makes a key of its own, kept in the keystore under a random
//! name, and seals the TLS key under it with XChaCha20-Poly1305. What is
//! stored in the peer store is the name, the nonce, and the sealed key; the
//! keystore's entry never leaves it except into this process.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use osm_vault_peer::{Keystore, KeystoreError};
use zeroize::Zeroizing;

/// The service the keystore's entries are kept under.
const SERVICE: &str = "org.opensecretmanager.transport-key";
/// The form of what [`SystemKeystore::seal`] returns.
const FORM: u8 = 1;
const NAME: usize = 16;
const NONCE: usize = 24;

/// The keystore of the system this app runs on.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemKeystore;

/// Whether a Linux `dbus-secret-service` error message indicates that no D-Bus
/// session bus or `org.freedesktop.secrets` service exists on the host (as
/// opposed to a present keyring that is locked, denied, or failed).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn secret_service_absent_message(message: &str) -> bool {
    let text = message.to_ascii_lowercase();
    text.contains("no dbus session or secret service provider found")
        || text.contains("unable to autolaunch a dbus-daemon")
        || text.contains("cannot spawn a message bus")
        || text.contains("failed to execute dbus-launch")
        || text.contains("using x11 for dbus-daemon autolaunch was disabled")
        || text.contains("not provided by any .service files")
        || text.contains("serviceunknown")
        || (text.contains("failed to connect to socket")
            && text.contains("no such file or directory"))
}

/// Returns `true` only on Linux when `keyring::Error::PlatformFailure` reports
/// that neither a D-Bus session bus nor a Secret Service provider is installed.
/// Locked keyrings and dismissed prompts surface as `NoStorageAccess` and stay
/// fail-closed (`Unavailable`).
#[cfg(target_os = "linux")]
pub(crate) fn linux_secret_service_absent(error: &keyring::Error) -> bool {
    matches!(error, keyring::Error::PlatformFailure(inner) if secret_service_absent_message(&inner.to_string()))
}

fn map_keyring_error(error: keyring::Error) -> KeystoreError {
    #[cfg(target_os = "linux")]
    if linux_secret_service_absent(&error) {
        return KeystoreError::Absent;
    }
    match error {
        keyring::Error::NoEntry => KeystoreError::Lost,
        _ => KeystoreError::Unavailable,
    }
}

fn entry(name: &[u8]) -> Result<keyring::Entry, KeystoreError> {
    keyring::Entry::new(SERVICE, &hex(name)).map_err(map_keyring_error)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What is bound to the sealed key besides the key: its form and its name,
/// so that a sealed key is opened only as what it was sealed as.
fn bound(name: &[u8]) -> Vec<u8> {
    [&b"osm transport key"[..], &[FORM], name].concat()
}

fn random<const N: usize>() -> Result<[u8; N], KeystoreError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| KeystoreError::Unavailable)?;
    Ok(bytes)
}

impl Keystore for SystemKeystore {
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let name = random::<NAME>()?;
        let wrapping = Zeroizing::new(random::<32>()?);
        let nonce = random::<NONCE>()?;
        let sealed = XChaCha20Poly1305::new(wrapping.as_ref().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key,
                    aad: &bound(&name),
                },
            )
            .map_err(|_| KeystoreError::Unavailable)?;
        entry(&name)?
            .set_secret(wrapping.as_ref())
            .map_err(map_keyring_error)?;
        Ok([&[FORM][..], &name, &nonce, &sealed].concat())
    }

    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        // Not in this form, or cut short: nothing this keystore sealed.
        let Some((&FORM, rest)) = sealed.split_first() else {
            return Err(KeystoreError::Lost);
        };
        if rest.len() < NAME + NONCE {
            return Err(KeystoreError::Lost);
        }
        let (name, rest) = rest.split_at(NAME);
        let (nonce, sealed) = rest.split_at(NONCE);
        let wrapping = Zeroizing::new(entry(name)?.get_secret().map_err(map_keyring_error)?);
        if wrapping.len() != 32 {
            return Err(KeystoreError::Lost);
        }
        XChaCha20Poly1305::new(wrapping.as_slice().into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &bound(name),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| KeystoreError::Lost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real keystore of the computer the tests run on. Not run by
    /// default: on macOS it can ask to use the login Keychain, and in a
    /// Linux container there is no Secret Service.
    #[test]
    #[ignore = "uses this computer's keystore"]
    fn the_system_keystore_seals_and_opens_a_key_and_refuses_what_it_did_not_seal() {
        let key = b"a key that identifies no device";
        let sealed = SystemKeystore.seal(key).unwrap();
        assert!(!sealed.windows(key.len()).any(|window| window == key));
        assert_eq!(SystemKeystore.open(&sealed).unwrap().as_slice(), key);

        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(SystemKeystore.open(&altered), Err(KeystoreError::Lost));
        let mut renamed = sealed.clone();
        renamed[1] ^= 1;
        assert_eq!(SystemKeystore.open(&renamed), Err(KeystoreError::Lost));

        entry(&sealed[1..1 + NAME])
            .unwrap()
            .delete_credential()
            .unwrap();
        assert_eq!(SystemKeystore.open(&sealed), Err(KeystoreError::Lost));
    }

    /// Run on Linux with no session bus (scripts/test-linux.sh): with no
    /// Secret Service to keep a key, nothing is sealed, and the TLS key is
    /// kept in the peer store as before.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a Linux system without a Secret Service"]
    fn without_a_secret_service_nothing_is_sealed() {
        assert_eq!(SystemKeystore.seal(b"a key"), Err(KeystoreError::Absent));
    }

    #[test]
    fn what_is_not_in_the_sealed_form_is_not_opened() {
        for sealed in [&[][..], &[FORM], &[2; 64], &[FORM; NAME + NONCE - 1]] {
            assert_eq!(SystemKeystore.open(sealed), Err(KeystoreError::Lost));
        }
    }

    #[test]
    fn secret_service_absence_classifier_distinguishes_absent_from_locked_or_denied() {
        assert!(secret_service_absent_message(
            "DBus error: Unable to autolaunch a dbus-daemon without a $DISPLAY for X11"
        ));
        assert!(secret_service_absent_message(
            "DBus error: The name org.freedesktop.secrets was not provided by any .service files"
        ));
        assert!(secret_service_absent_message(
            "No DBus session or Secret Service provider found"
        ));
        assert!(!secret_service_absent_message(
            "Secret Service: object locked"
        ));
        assert!(!secret_service_absent_message(
            "Secret Service: unlock prompt was dismissed"
        ));
        assert!(!secret_service_absent_message("DBus error: AccessDenied"));
        assert_eq!(
            map_keyring_error(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::other("Secret Service: object locked")
            ))),
            KeystoreError::Unavailable
        );
    }
}
