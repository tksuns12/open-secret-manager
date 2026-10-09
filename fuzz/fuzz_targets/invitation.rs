//! An invitation as the owner pastes it. One read is written back as the
//! text given, without the spaces around it: it has one form.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_vault_peer::Invitation;

fuzz_target!(|text: &str| {
    if let Ok(invitation) = Invitation::decode(text) {
        assert_eq!(invitation.encode().unwrap().as_str(), text.trim());
    }
});
