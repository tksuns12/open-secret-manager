use std::sync::{Mutex, PoisonError};

use arboard::SetExtWindows;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

struct Served {
    key: [u8; 32],
    copies: isize,
    last: Option<(isize, [u8; 32])>,
}

static SERVED: Mutex<Option<Served>> = Mutex::new(None);

fn keyed_digest(key: &[u8; 32], text: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-clipboard-v1");
    hasher.update(key);
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Puts `text` on the Windows clipboard, excluded from clipboard monitoring,
/// local clipboard history, and Windows Cloud Clipboard.
pub(crate) fn copy_secret(text: &str) -> Option<isize> {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    if served.is_none() {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).ok()?;
        *served = Some(Served {
            key,
            copies: 0,
            last: None,
        });
    }
    let served = served.as_mut()?;
    let mut clipboard = arboard::Clipboard::new().ok()?;
    clipboard
        .set()
        .exclude_from_monitoring()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(text.to_owned())
        .ok()?;
    served.copies += 1;
    let digest = keyed_digest(&served.key, text);
    served.last = Some((served.copies, digest));
    Some(served.copies)
}

/// Clears the Windows clipboard if it still holds the last secret put there by
/// [`copy_secret`], and, given `copy`, only if that secret was that copy.
pub(crate) fn clear(copy: Option<isize>) {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(served) = served.as_mut() else {
        return;
    };
    let Some((last, expected)) = served.last else {
        return;
    };
    if copy.is_some_and(|copy| copy != last) {
        return;
    }
    if let Ok(mut clipboard) = arboard::Clipboard::new() {
        match clipboard.get_text() {
            Ok(current) => {
                let current = Zeroizing::new(current);
                if keyed_digest(&served.key, &current) == expected {
                    let _ = clipboard.clear();
                }
            }
            Err(_) => {
                let _ = clipboard.clear();
            }
        }
    }
    served.last = None;
}
