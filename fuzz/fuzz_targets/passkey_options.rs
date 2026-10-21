//! What a site or an app asks of a passkey, as a browser or Android hands
//! it on: a request to make one or to sign in, read for a page of
//! https://www.example.test or for an app, as the first byte says. A
//! request is refused, or is one whose every check passed; and a passkey's
//! own JSON reads back as it was written.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_origin::Origin;
use osm_vault_core::passkey::{rp_id_allowed, rp_id_valid, Registering, Signing};
use osm_vault_core::Passkey;

fuzz_target!(|data: &[u8]| {
    let Some((&how, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let page = Origin::parse("https://www.example.test").unwrap();
    let origin = (how & 2 != 0).then_some(&page);
    let site_checked = |rp_id: &str| {
        assert!(rp_id_valid(rp_id), "{rp_id}");
        if let Some(origin) = origin {
            assert!(rp_id_allowed(rp_id, origin), "{rp_id}");
        }
    };
    match how % 4 {
        0 | 2 => {
            if let Ok(request) = Registering::from_options(text, origin) {
                site_checked(&request.rp_id);
                assert!((1..=64).contains(&request.user_handle.len()));
                assert!((1..=1024).contains(&request.challenge.len()));
                assert!(request.user_name.chars().count() <= 256);
                assert!(request.user_display_name.chars().count() <= 256);
                assert!(request.rp_name.chars().count() <= 256);
                assert!(request.exclude.len() <= 256);
                assert!(request
                    .exclude
                    .iter()
                    .all(|id| (1..=1023).contains(&id.len())));
            }
        }
        1 | 3 => {
            if let Ok(request) = Signing::from_options(text, origin) {
                site_checked(&request.rp_id);
                assert!((1..=1024).contains(&request.challenge.len()));
                assert!(request.allowed.len() <= 256);
                assert!(request
                    .allowed
                    .iter()
                    .all(|id| (1..=1023).contains(&id.len())));
            }
        }
        _ => unreachable!(),
    }
    if how & 4 != 0 {
        if let Ok(passkey) = serde_json::from_str::<Passkey>(text) {
            let written = serde_json::to_string(&passkey).unwrap();
            assert!(serde_json::from_str::<Passkey>(&written).unwrap() == passkey);
        }
    }
});
