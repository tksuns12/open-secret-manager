//! What a peer sends is read without a crash and is either refused or
//! exactly what the protocol allows, and no sequence of messages makes a
//! device do more than the protocol asks of it. The cases are new on every
//! run; a failing one is kept in `proptest-regressions/`.

use std::collections::BTreeSet;

use osm_vault_core::{EncryptedRevision, Item, Vault};
use proptest::{prelude::*, test_runner::TestRunner};
use tempfile::tempdir;

use crate::{
    session::inventory::{from_hex, summary, RevisionId},
    wire::{decode_body, encode_frame, FrameDecoder, MAX_FRAME_BYTES},
    EnrollmentGrant, Invitation, JoinRequest, SyncMessage, SyncSession, PROTOCOL_VERSION,
};

/// A number written in more bytes than it needs is another form of the
/// same message, which postcard alone takes; it is refused, in a frame and
/// in an invitation. Fuzzing found it (Phase 13): the frozen invitation
/// with its last number, 90, written as two bytes was read as the same.
#[test]
fn a_number_written_in_more_bytes_than_it_needs_is_refused() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let longer = |bytes: &[u8], at: usize| {
        assert!(bytes[at] < 0x80, "a one-byte number at {at}");
        [&bytes[..at], &[bytes[at] | 0x80, 0x00], &bytes[at + 1..]].concat()
    };

    let sync: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/sync.json")).unwrap();
    let body = crate::fixture::unhex(sync["hello"]["body"].as_str().unwrap());
    assert!(decode_body::<SyncMessage>(&body).is_ok());
    // A message's kind is its first number.
    assert!(decode_body::<SyncMessage>(&longer(&body, 0)).is_err());

    let pairing: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/pairing.json")).unwrap();
    let text = pairing["invitation_text"].as_str().unwrap();
    assert!(Invitation::decode(text).is_ok());
    let bytes = Base64UrlUnpadded::decode_vec(text.strip_prefix("OSM-PAIR1-").unwrap()).unwrap();
    let long = format!(
        "OSM-PAIR1-{}",
        Base64UrlUnpadded::encode_string(&longer(&bytes, bytes.len() - 1))
    );
    assert!(Invitation::decode(&long).is_err());
}

proptest! {
    /// Any bytes read as a message are refused, or are a message that is
    /// sent as exactly those bytes. A peer cannot pass one message off in
    /// two forms.
    #[test]
    fn any_bytes_are_refused_or_are_the_one_form_of_a_message(
        body in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        fn canonical<T: serde::Serialize + serde::de::DeserializeOwned>(body: &[u8]) -> Result<(), TestCaseError> {
            if let Ok(message) = decode_body::<T>(body) {
                prop_assert_eq!(&encode_frame(&message).unwrap()[4..], body);
            }
            Ok(())
        }
        canonical::<SyncMessage>(&body)?;
        canonical::<JoinRequest>(&body)?;
        canonical::<EnrollmentGrant>(&body)?;
    }

    /// Frames are the same however the bytes arrive, and a declared length
    /// over the bound is refused before anything is kept.
    #[test]
    fn frames_are_the_same_however_the_bytes_arrive(
        bodies in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 1..6),
        cuts in prop::collection::vec(1_usize..40, 0..20),
        oversize in prop::option::of(MAX_FRAME_BYTES as u32 + 1..u32::MAX),
    ) {
        let mut stream = Vec::new();
        for body in &bodies {
            stream.extend_from_slice(&(body.len() as u32).to_be_bytes());
            stream.extend_from_slice(body);
        }
        if let Some(length) = oversize {
            stream.extend_from_slice(&length.to_be_bytes());
        }
        let mut decoder = FrameDecoder::default();
        let mut read = Vec::new();
        let mut at = 0;
        let mut refused = false;
        for cut in cuts.iter().copied().chain(std::iter::repeat(64)) {
            if at >= stream.len() {
                break;
            }
            let end = (at + cut).min(stream.len());
            if decoder.push(&stream[at..end]).is_err() {
                refused = true;
                break;
            }
            at = end;
            // A length over the bound behind frames that are still waiting
            // is refused when it comes to be read.
            loop {
                match decoder.next_body() {
                    Ok(Some(body)) => read.push(body),
                    Ok(None) => break,
                    Err(_) => {
                        refused = true;
                        break;
                    }
                }
            }
            if refused {
                break;
            }
        }
        prop_assert_eq!(read, bodies);
        prop_assert_eq!(refused, oversize.is_some());
    }

    /// An invitation is read only from its own text.
    #[test]
    fn an_invitation_is_read_only_from_its_own_text(text in prop_oneof![
        "OSM-PAIR1-[A-Za-z0-9_-]{0,300}",
        ".{0,80}",
    ]) {
        if let Ok(invitation) = Invitation::decode(&text) {
            let written = invitation.encode().unwrap();
            prop_assert_eq!(written.as_str(), text.trim());
        }
    }
}

proptest! {
    /// Any one character of an invitation that carries a relay changed, or
    /// the end cut off, reads as nothing or back as exactly its own text.
    #[test]
    fn a_damaged_invitation_with_a_relay_is_refused_or_read_as_itself(
        at in 10usize..340,
        letter in "[A-Za-z0-9_-]",
        cut in 0usize..3,
    ) {
        let frozen: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/pairing-relay.json")).unwrap();
        let mut text = frozen["invitation_text"].as_str().unwrap().to_owned();
        let at = at.min(text.len() - 1);
        text.replace_range(at..=at, &letter);
        text.truncate(text.len() - cut);
        if let Ok(invitation) = Invitation::decode(&text) {
            let written = invitation.encode().unwrap();
            prop_assert_eq!(written.as_str(), text.trim());
        }
    }
}

/// A vault with a few items for a sync session to send.
fn vault_with_items(dir: &std::path::Path) -> Vault {
    let (mut vault, _) =
        Vault::create(dir.join("vault.sqlite3"), "property test password").unwrap();
    for n in 0..5 {
        let mut item = Item::new(format!("Item {n}"));
        item.notes = "x".repeat(100);
        vault.put(item).unwrap();
    }
    vault
}

/// Messages a peer might send, in any order and any number.
fn messages(
    vault_id: [u8; 32],
    stored: Vec<EncryptedRevision>,
) -> impl Strategy<Value = Vec<SyncMessage>> {
    let ids: Vec<RevisionId> = stored
        .iter()
        .map(|revision| from_hex(&revision.revision_id()).unwrap())
        .collect();
    let id = prop_oneof![prop::sample::select(ids.clone()), any::<[u8; 32]>()];
    // The summary of none, of some of the stored revisions, of all of them,
    // or anything, of any length.
    let summary = prop_oneof![
        prop::sample::subsequence(ids.clone(), 0..=ids.len()).prop_map(|mut some| {
            some.sort_unstable();
            summary(&some)
        }),
        prop::collection::vec(any::<[u8; 32]>(), 254..258),
    ];
    let revision = (prop::sample::select(stored), any::<u8>(), any::<usize>()).prop_map(
        |(mut revision, change, at)| {
            match change % 4 {
                0 => {}
                1 => {
                    let at = at % revision.ciphertext.len();
                    revision.ciphertext[at] ^= 1;
                }
                2 => revision.parents = vec![format!("{change:02x}").repeat(32)],
                _ => revision.key_epoch = u64::from(change) + 2,
            }
            revision
        },
    );
    let message = prop_oneof![
        3 => (prop_oneof![Just(PROTOCOL_VERSION), any::<u16>()], prop_oneof![Just(vault_id), any::<[u8; 32]>()], any::<Option<u16>>())
            .prop_map(|(version, vault_id, listen_port)| SyncMessage::Hello { version, vault_id, listen_port }),
        3 => summary.prop_map(|buckets| SyncMessage::Summary { buckets }),
        3 => (prop::collection::vec(id.clone(), 0..8), any::<bool>()).prop_map(|(mut ids, sorted)| {
            if sorted {
                ids.sort_unstable();
            }
            SyncMessage::Ids { ids }
        }),
        3 => prop::collection::vec(id, 0..8).prop_map(|ids| SyncMessage::Need { ids }),
        2 => prop::collection::vec(revision, 0..4).prop_map(|revisions| SyncMessage::Revisions { revisions }),
        3 => Just(SyncMessage::Done),
        1 => Just(SyncMessage::Finished),
    ];
    let hello = Just(SyncMessage::Hello {
        version: PROTOCOL_VERSION,
        vault_id,
        listen_port: None,
    });
    (hello, prop::collection::vec(message, 0..40))
        .prop_map(|(hello, rest)| [vec![hello], rest].concat())
}

/// Hands `message` to the session and takes what it sends in answer.
fn answer(
    session: &mut SyncSession,
    vault: &mut Vault,
    message: SyncMessage,
) -> crate::Result<Vec<SyncMessage>> {
    session.handle(vault, message)?;
    let mut sent = Vec::new();
    while let Some(message) = session.next_message(vault)? {
        sent.push(message);
    }
    Ok(sent)
}

/// However a peer behaves, a session ends in a refusal or goes on within
/// the protocol: it sends each stored revision at most once per round the
/// protocol has, it asks for missing parents a bounded number of times,
/// and nothing a peer sends changes what the vault has accepted.
#[test]
fn a_sync_session_does_no_more_than_the_protocol_asks_whatever_the_peer_sends() {
    let dir = tempdir().unwrap();
    let vault = std::cell::RefCell::new(vault_with_items(dir.path()));
    let mut vault_ref = vault.borrow_mut();
    let vault_now: &mut Vault = &mut vault_ref;
    let stored: Vec<EncryptedRevision> = vault_now.encrypted_revisions().unwrap();
    let accepted: BTreeSet<String> = vault_now.revision_ids().unwrap().into_iter().collect();
    let vault_id = vault_now.vault_id();
    drop(vault_ref);
    let mut runner = TestRunner::default();
    runner
        .run(&messages(vault_id, stored.clone()), |messages| {
            let mut vault = vault.borrow_mut();
            let vault = &mut *vault;
            let mut session = SyncSession::start(vault, None).unwrap();
            while session.next_message(vault).unwrap().is_some() {}
            let (mut sent, mut asked) = (0, 0);
            for message in messages {
                match answer(&mut session, vault, message) {
                    Ok(replies) => {
                        for reply in replies {
                            match reply {
                                SyncMessage::Revisions { revisions } => sent += revisions.len(),
                                SyncMessage::Need { .. } => asked += 1,
                                _ => {}
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // One answer to the peer's IDs and one to each of the rounds in
            // which it may ask for missing parents.
            prop_assert!(
                sent <= stored.len() * 9,
                "sent {sent} revisions of {}",
                stored.len()
            );
            prop_assert!(asked <= 8, "asked {asked} times");
            prop_assert_eq!(
                &vault
                    .revision_ids()
                    .unwrap()
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                &accepted
            );
            Ok(())
        })
        .unwrap();
}

/// A peer that sends its summary or its IDs again and again, asks for
/// everything again and again, or says it is done again and again is
/// stopped: the protocol has one summary and one list of IDs, and as many
/// requests and answers for missing parents as it has rounds.
#[test]
fn a_peer_that_repeats_itself_is_stopped() {
    let dir = tempdir().unwrap();
    let mut vault = vault_with_items(dir.path());
    let ids: Vec<RevisionId> = vault
        .revision_ids()
        .unwrap()
        .iter()
        .map(|id| from_hex(id).unwrap())
        .collect();
    let vault_id = vault.vault_id();
    let hello = SyncMessage::Hello {
        version: PROTOCOL_VERSION,
        vault_id,
        listen_port: None,
    };
    let held = vault.held_revision_ids().unwrap();
    // A peer that holds the same, and one that holds nothing.
    let same = SyncMessage::Summary {
        buckets: summary(&held),
    };
    let nothing = SyncMessage::Summary {
        buckets: summary(&[]),
    };
    for (opening, repeated) in [
        (vec![hello.clone()], same.clone()),
        (
            vec![hello.clone(), nothing.clone()],
            SyncMessage::Ids { ids: Vec::new() },
        ),
        (
            vec![hello.clone(), same.clone()],
            SyncMessage::Need { ids: ids.clone() },
        ),
        (vec![hello.clone(), same.clone()], SyncMessage::Done),
    ] {
        let mut session = SyncSession::start(&vault, None).unwrap();
        while session.next_message(&vault).unwrap().is_some() {}
        for message in opening {
            answer(&mut session, &mut vault, message).unwrap();
        }
        let mut sent = 0;
        let mut refused = false;
        for _ in 0..20 {
            match answer(&mut session, &mut vault, repeated.clone()) {
                Ok(replies) => {
                    for reply in replies {
                        if let SyncMessage::Revisions { revisions } = reply {
                            sent += revisions.len();
                        }
                    }
                }
                Err(_) => {
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "{repeated:?} was taken twenty times");
        assert!(sent <= ids.len() * 9, "sent {sent}");
    }
}

/// A request for more parents than one round may ask for is refused.
#[test]
fn a_request_for_more_than_65_536_parents_is_refused() {
    let dir = tempdir().unwrap();
    let mut vault = vault_with_items(dir.path());
    let vault_id = vault.vault_id();
    let held = vault.held_revision_ids().unwrap();
    for (count, refused) in [(65_536, false), (65_537, true)] {
        let mut session = SyncSession::start(&vault, None).unwrap();
        for message in [
            SyncMessage::Hello {
                version: PROTOCOL_VERSION,
                vault_id,
                listen_port: None,
            },
            SyncMessage::Summary {
                buckets: summary(&held),
            },
        ] {
            answer(&mut session, &mut vault, message).unwrap();
        }
        let need = SyncMessage::Need {
            ids: vec![[0; 32]; count],
        };
        assert_eq!(answer(&mut session, &mut vault, need).is_err(), refused);
    }
}

/// Before a peer is known to be a member, what it sends is bounded small,
/// and a declared length is held only as far as the bytes arrive.
#[tokio::test]
async fn a_message_from_a_peer_not_yet_known_is_bounded_small() {
    use tokio::io::AsyncWriteExt;

    use crate::{
        transport::{read_frame_within, MAX_HANDSHAKE_FRAME_BYTES},
        Error,
    };

    let (mut peer, mut here) = tokio::io::duplex(1024);
    peer.write_all(&(MAX_HANDSHAKE_FRAME_BYTES as u32 + 1).to_be_bytes())
        .await
        .unwrap();
    assert!(matches!(
        read_frame_within::<_, JoinRequest>(&mut here, MAX_HANDSHAKE_FRAME_BYTES).await,
        Err(Error::FrameTooLarge)
    ));

    // A length the peer never fills, then it goes away.
    let (mut peer, mut here) = tokio::io::duplex(1024);
    peer.write_all(&1000_u32.to_be_bytes()).await.unwrap();
    peer.write_all(&[0; 10]).await.unwrap();
    drop(peer);
    assert!(matches!(
        read_frame_within::<_, JoinRequest>(&mut here, MAX_HANDSHAKE_FRAME_BYTES).await,
        Err(Error::ConnectionClosed)
    ));
}
