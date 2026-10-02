//! The frozen opening exchange of a connection between members.

use serde_json::json;

use super::*;
use crate::fixture::{counting, frozen, sent, unhex};

#[test]
fn the_opening_exchange_between_members_is_the_frozen_one() {
    let roster = vec![
        MemberContact {
            device_id: counting(0x40),
            transport_pin: counting(0x20),
            address: Some("192.0.2.10:47821".into()),
        },
        MemberContact {
            device_id: counting(0xa0),
            transport_pin: counting(0x01),
            address: None,
        },
    ];
    let open = |channel, listen_port, roster| Open {
        version: MEMBER_PROTOCOL_VERSION,
        vault_id: counting(0x10),
        channel,
        listen_port,
        roster,
    };
    let made = json!({
        "about": "The first frames of a connection between two of a vault's devices, as this code made them when the formats were frozen: postcard, in a frame of a 4-byte big-endian length and the body. After the reply the control channel carries JSON bodies in such frames, and the sync channel the sync messages.",
        "version": MEMBER_PROTOCOL_VERSION,
        "open_control": sent(&open(Channel::Control, Some(47821), roster.clone())),
        "open_sync_with_nothing_optional": sent(&open(Channel::Sync, None, Vec::new())),
        "reply_welcome": sent(&OpenReply::Welcome { roster: roster.clone() }),
        "reply_unsupported_version": sent(&OpenReply::UnsupportedVersion),
        "reply_vault_mismatch": sent(&OpenReply::VaultMismatch),
        "reply_not_a_member": sent(&OpenReply::NotAMember),
        "reply_removed": sent(&OpenReply::Removed),
    });
    let frozen = frozen("members.json", &made);
    assert_eq!(frozen["version"], 2);

    // And back.
    let body = |name: &str| unhex(frozen[name]["body"].as_str().unwrap());
    let read: Open = crate::wire::decode_body(&body("open_control")).unwrap();
    assert_eq!(
        (read.version, read.channel, read.listen_port, read.roster),
        (2, Channel::Control, Some(47821), roster.clone())
    );
    let read: OpenReply = crate::wire::decode_body(&body("reply_welcome")).unwrap();
    assert!(matches!(read, OpenReply::Welcome { roster: read } if read == roster));
    for (name, wanted) in [
        ("reply_unsupported_version", 1),
        ("reply_vault_mismatch", 2),
        ("reply_not_a_member", 3),
        ("reply_removed", 4),
    ] {
        // Each refusal is the one byte that names it.
        assert_eq!(body(name), [wanted], "{name}");
    }
    // A reply this build does not know is not taken for one it does.
    assert!(crate::wire::decode_body::<OpenReply>(&[5]).is_err());
    assert!(crate::wire::decode_body::<OpenReply>(&[4, 0]).is_err());
}
