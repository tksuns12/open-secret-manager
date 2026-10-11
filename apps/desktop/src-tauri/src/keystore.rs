//! The system's keystore on the desktop, which seals this device's TLS key
//! (see `osm_vault_peer::Keystore`): the login Keychain on macOS, the
//! Secret Service (GNOME Keyring, KWallet) on Linux.
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

fn entry(name: &[u8]) -> Result<keyring::Entry, KeystoreError> {
    keyring::Entry::new(SERVICE, &hex(name)).map_err(|_| KeystoreError::Unavailable)
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
            .map_err(|_| KeystoreError::Unavailable)?;
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
        let wrapping = Zeroizing::new(entry(name)?.get_secret().map_err(|error| match error {
            keyring::Error::NoEntry => KeystoreError::Lost,
            _ => KeystoreError::Unavailable,
        })?);
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
        assert_eq!(
            SystemKeystore.seal(b"a key"),
            Err(KeystoreError::Unavailable)
        );
    }

    #[test]
    fn what_is_not_in_the_sealed_form_is_not_opened() {
        for sealed in [&[][..], &[FORM], &[2; 64], &[FORM; NAME + NONCE - 1]] {
            assert_eq!(SystemKeystore.open(sealed), Err(KeystoreError::Lost));
        }
    }
}
