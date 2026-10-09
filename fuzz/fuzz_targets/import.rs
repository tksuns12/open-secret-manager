//! A file from another password manager, as the owner imports it: read
//! in each of the formats, it is a preview or refused, never a crash. The
//! first byte picks the format.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_vault_core::{preview_import, ImportFormat};

fuzz_target!(|data: &[u8]| {
    let Some((&which, bytes)) = data.split_first() else {
        return;
    };
    let format = match which % 3 {
        0 => ImportFormat::BitwardenJson,
        1 => ImportFormat::ChromeCsv,
        _ => ImportFormat::FirefoxCsv,
    };
    let _ = preview_import(format, bytes);
});
