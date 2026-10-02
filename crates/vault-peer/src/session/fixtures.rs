//! The frozen sync messages.

use osm_vault_core::EncryptedRevision;
use serde_json::json;

use super::*;
use crate::fixture::{counting, frozen, sent, unhex};

#[test]
fn sync_messages_are_the_frozen_ones() {
    let ids = vec!["1".repeat(64), "a".repeat(64)];
    // A revision as the core seals one; here only its shape matters.
    let revision = EncryptedRevision {
        format_version: 2,
        vault_id: counting(0x10),
        item_id: "vector-item".into(),
        parents: ids.clone(),
        key_epoch: 3,
        author_device_id: counting(0x40),
        nonce: counting(0xe0),
        ciphertext: counting::<20>(0x80).to_vec(),
        tombstone: false,
        signature: counting::<64>(0xc0).to_vec(),
    };
    let made = json!({
        "about": "The messages of a sync session, as this code made them when the formats were frozen: postcard, in a frame of a 4-byte big-endian length and the body. A revision is the core's sealed revision, field by field.",
        "version": PROTOCOL_VERSION,
        "hello": sent(&SyncMessage::Hello { version: PROTOCOL_VERSION, vault_id: counting(0x10), listen_port: Some(47820) }),
        "hello_without_a_port": sent(&SyncMessage::Hello { version: PROTOCOL_VERSION, vault_id: counting(0x10), listen_port: None }),
        "inventory": sent(&SyncMessage::Inventory { revisions: ids.clone() }),
        "revisions": sent(&SyncMessage::Revisions { revisions: vec![revision.clone()] }),
        "need": sent(&SyncMessage::Need { revisions: ids.clone() }),
        "done": sent(&SyncMessage::Done),
        "finished": sent(&SyncMessage::Finished),
    });
    let frozen = frozen("sync.json", &made);
    assert_eq!(frozen["version"], 1);

    // And back.
    let read = |name: &str| -> SyncMessage {
        crate::wire::decode_body(&unhex(frozen[name]["body"].as_str().unwrap())).unwrap()
    };
    assert!(matches!(
        read("hello"),
        SyncMessage::Hello {
            version: 1,
            listen_port: Some(47820),
            ..
        }
    ));
    assert!(matches!(read("inventory"), SyncMessage::Inventory { revisions } if revisions == ids));
    assert!(
        matches!(read("revisions"), SyncMessage::Revisions { revisions } if revisions == [revision])
    );
    assert!(matches!(read("need"), SyncMessage::Need { revisions } if revisions == ids));
    assert!(matches!(read("done"), SyncMessage::Done));
    assert!(matches!(read("finished"), SyncMessage::Finished));
    // A kind of message this build does not know, and bytes after a
    // message, are refused.
    assert!(crate::wire::decode_body::<SyncMessage>(&[6]).is_err());
    assert!(crate::wire::decode_body::<SyncMessage>(&[4, 0]).is_err());
}
