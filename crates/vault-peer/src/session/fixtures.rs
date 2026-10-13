//! The frozen sync messages: those of version 2, which this code speaks, and
//! the `Hello` of version 1, which it reads only to refuse by its version.

use osm_vault_core::EncryptedRevision;
use serde_json::json;

use super::*;
use crate::fixture::{counting, frozen, hex, sent, unhex};

#[test]
fn sync_messages_are_the_frozen_ones() {
    let ids: Vec<RevisionId> = vec![counting(0x10), counting(0xa0)];
    // A revision as the core seals one; here only its shape matters.
    let revision = EncryptedRevision {
        format_version: 2,
        vault_id: counting(0x10),
        item_id: "vector-item".into(),
        parents: ids.iter().map(inventory::to_hex).collect(),
        key_epoch: 3,
        author_device_id: counting(0x40),
        nonce: counting(0xe0),
        ciphertext: counting::<20>(0x80).to_vec(),
        tombstone: false,
        signature: counting::<64>(0xc0).to_vec(),
    };
    let summary = inventory::summary(&ids);
    let made = json!({
        "about": "The messages of a sync session of version 2, as this code made them when the version was frozen: postcard, in a frame of a 4-byte big-endian length and the body. A revision ID is its 32 bytes. A summary has a digest for each of 256 buckets, bucket b holding the IDs whose first byte is b: SHA-256 of the label osm-sync-bucket-v2 and a zero byte, then the bucket's IDs in ascending order. `summary` is that of the two IDs of `ids`, `empty_bucket` the digest of a bucket with none. A revision is the core's sealed revision, field by field.",
        "version": PROTOCOL_VERSION,
        "empty_bucket": hex(&summary[1]),
        "bucket_of_the_first_id": hex(&summary[0x10]),
        "hello": sent(&SyncMessage::Hello { version: PROTOCOL_VERSION, vault_id: counting(0x10), listen_port: Some(47820) }),
        "hello_without_a_port": sent(&SyncMessage::Hello { version: PROTOCOL_VERSION, vault_id: counting(0x10), listen_port: None }),
        "summary": sent(&SyncMessage::Summary { buckets: summary.clone() }),
        "ids": sent(&SyncMessage::Ids { ids: ids.clone() }),
        "no_ids": sent(&SyncMessage::Ids { ids: Vec::new() }),
        "revisions": sent(&SyncMessage::Revisions { revisions: vec![revision.clone()] }),
        "need": sent(&SyncMessage::Need { ids: ids.clone() }),
        "done": sent(&SyncMessage::Done),
        "finished": sent(&SyncMessage::Finished),
    });
    let frozen = frozen("sync-2.json", &made);
    assert_eq!(frozen["version"], 2);

    // And back.
    let read = |name: &str| -> SyncMessage {
        crate::wire::decode_body(&unhex(frozen[name]["body"].as_str().unwrap())).unwrap()
    };
    assert!(matches!(
        read("hello"),
        SyncMessage::Hello {
            version: 2,
            listen_port: Some(47820),
            ..
        }
    ));
    assert!(matches!(read("summary"), SyncMessage::Summary { buckets } if buckets == summary));
    assert!(matches!(read("ids"), SyncMessage::Ids { ids: read } if read == ids));
    assert!(matches!(read("no_ids"), SyncMessage::Ids { ids } if ids.is_empty()));
    assert!(
        matches!(read("revisions"), SyncMessage::Revisions { revisions } if revisions == [revision])
    );
    assert!(matches!(read("need"), SyncMessage::Need { ids: read } if read == ids));
    assert!(matches!(read("done"), SyncMessage::Done));
    assert!(matches!(read("finished"), SyncMessage::Finished));
    // A kind of message this build does not know, and bytes after a
    // message, are refused.
    assert!(crate::wire::decode_body::<SyncMessage>(&[7]).is_err());
    assert!(crate::wire::decode_body::<SyncMessage>(&[5, 0]).is_err());
}

/// A `Hello` has the same form in both versions but for the version, so
/// each side reads the other's and refuses the session by its version.
#[test]
fn a_hello_of_version_1_is_read_and_one_of_version_2_has_its_form() {
    let first: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/sync.json")).unwrap();
    let old = unhex(first["hello"]["body"].as_str().unwrap());
    assert!(matches!(
        crate::wire::decode_body::<SyncMessage>(&old).unwrap(),
        SyncMessage::Hello {
            version: 1,
            listen_port: Some(47820),
            ..
        }
    ));
    let new = crate::wire::encode_frame(&SyncMessage::Hello {
        version: PROTOCOL_VERSION,
        vault_id: counting(0x10),
        listen_port: Some(47820),
    })
    .unwrap();
    assert_eq!((old[0], old[1], new[4], new[5]), (0, 1, 0, 2));
    assert_eq!(old[2..], new[6..]);
}
