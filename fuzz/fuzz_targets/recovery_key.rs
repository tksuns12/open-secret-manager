//! A recovery key as the owner types it. A key read is written back
//! exactly as it was given: it has one form.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_vault_core::RecoveryKey;

fuzz_target!(|text: &str| {
    if let Ok(key) = RecoveryKey::parse(text) {
        assert_eq!(key.to_string(), text);
    }
});
