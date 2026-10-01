use std::path::Path;

use osm_vault_core::{Item, Vault};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tempfile::tempdir;

use crate::{
    approve_join, invite, review_join,
    wire::{decode_body, encode_frame, FrameDecoder, MAX_FRAME_BYTES},
    Error, Invitation, JoinGrant, JoinRequest, Joiner, PeerStore, SyncMessage, SyncReport,
    SyncSession,
};

const NOW: u64 = 1_800_000_000;
/// The sans-IO tests never open a TLS connection, so any pin will do.
const JOINER_PIN: [u8; 32] = [7; 32];

fn address() -> Vec<String> {
    vec!["127.0.0.1:1".to_owned()]
}

struct Device {
    vault: Vault,
    invitations: InvitationStore,
    peers: PeerStore,
}

fn inviter(dir: &Path) -> Device {
    let (vault, _) = Vault::create(dir.join("a.db"), "inviter password").unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    }
}

fn login(title: &str, password: &str) -> Item {
    let mut item = Item::new(title);
    item.username = "owner@example.test".into();
    item.password = password.into();
    item
}

/// Sends a pairing message through the real frame encoding.
fn over_wire<T: serde::Serialize + serde::de::DeserializeOwned>(message: &T) -> T {
    let frame = encode_frame(message).unwrap();
    let mut decoder = FrameDecoder::default();
    decoder.push(&frame).unwrap();
    decode_body(&decoder.next_body().unwrap().unwrap()).unwrap()
}

/// Runs the full owner-confirmed pairing and returns the joined device.
fn pair(dir: &Path, a: &mut Device) -> Device {
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        300,
    )
    .unwrap();
    let code = invitation.encode().unwrap();
    let (joiner, request) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW + 1).unwrap();
    let review = review_join(
        &a.vault,
        &a.invitations,
        &mut a.peers,
        over_wire(&request),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(review.sas(), joiner.sas());
    let grant = approve_join(
        &mut a.vault,
        &mut a.invitations,
        &mut a.peers,
        review,
        Some(47820),
        NOW + 3,
    )
    .unwrap();
    let mut peers = PeerStore::open_in_memory().unwrap();
    let vault = joiner
        .finish(
            &over_wire(&grant),
            true,
            dir.join("b.db"),
            "joiner password",
            &mut peers,
            NOW + 4,
        )
        .unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers,
    }
}

/// What the in-memory transport does to one framed message.
enum Fault {
    Deliver,
    /// Deliver a modified message.
    Replace(SyncMessage),
    /// Cut the connection: nothing more is delivered in either direction.
    Disconnect,
}

/// Moves framed messages between two sessions until both complete, the
/// transport is cut, or a step limit is hit. Returns whether both completed.
fn run_sync(
    a: &mut Vault,
    b: &mut Vault,
    mut fault: impl FnMut(bool, &SyncMessage) -> Fault,
) -> Result<(bool, SyncReport, SyncReport), Error> {
    let (mut session_a, opening_a) = SyncSession::start(a, None)?;
    let (mut session_b, opening_b) = SyncSession::start(b, None)?;
    // (to_b, message)
    let mut queue: std::collections::VecDeque<(bool, Vec<u8>)> = opening_a
        .iter()
        .map(|message| (true, encode_frame(message).unwrap()))
        .chain(
            opening_b
                .iter()
                .map(|message| (false, encode_frame(message).unwrap())),
        )
        .collect();
    let mut steps = 0;
    while let Some((to_b, frame)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 10_000, "sync did not terminate");
        let mut decoder = FrameDecoder::default();
        decoder.push(&frame)?;
        let message: SyncMessage = decode_body(&decoder.next_body()?.unwrap())?;
        let message = match fault(to_b, &message) {
            Fault::Deliver => message,
            Fault::Replace(replacement) => replacement,
            Fault::Disconnect => {
                return Ok((
                    false,
                    session_a.report().clone(),
                    session_b.report().clone(),
                ))
            }
        };
        let replies = if to_b {
            session_b.handle(b, message)?
        } else {
            session_a.handle(a, message)?
        };
        for reply in replies {
            queue.push_back((!to_b, encode_frame(&reply)?));
        }
        if session_a.is_complete() && session_b.is_complete() && queue.is_empty() {
            break;
        }
    }
    Ok((
        session_a.is_complete() && session_b.is_complete(),
        session_a.report().clone(),
        session_b.report().clone(),
    ))
}

fn sync(a: &mut Vault, b: &mut Vault) -> (SyncReport, SyncReport) {
    let (complete, report_a, report_b) = run_sync(a, b, |_, _| Fault::Deliver).unwrap();
    assert!(complete);
    (report_a, report_b)
}

fn ids(vault: &Vault) -> std::collections::BTreeSet<String> {
    vault.revision_ids().unwrap().into_iter().collect()
}

#[test]
fn paired_devices_sync_in_both_directions() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let first = login("Mail", "mail password");
    let second = login("Bank", "bank password");
    a.vault.put(first.clone()).unwrap();
    a.vault.put(second.clone()).unwrap();

    let mut b = pair(dir.path(), &mut a);
    assert_eq!(b.vault.vault_id(), a.vault.vault_id());
    assert_ne!(b.vault.device_id(), a.vault.device_id());
    assert_eq!(
        a.peers.peers().unwrap()[0].device_id,
        b.vault.device_id().unwrap()
    );
    assert_eq!(
        b.peers.peers().unwrap()[0].device_id,
        a.vault.device_id().unwrap()
    );
    // The joiner reaches the inviter at its sync port from the signed grant,
    // not at the pairing port from the invitation, which closes after pairing.
    assert_eq!(
        b.peers.peers().unwrap()[0].address.as_deref(),
        Some("127.0.0.1:47820")
    );

    // Initial sync copies the vault to the new device.
    let (to_b, _) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 2);
    assert_eq!(
        b.vault.get(&first.id).unwrap().item.password,
        "mail password"
    );
    assert_eq!(b.vault.list().unwrap().len(), 2);

    // An edit on the new device is signed by it and accepted, not held.
    let current = b.vault.get(&second.id).unwrap();
    let mut edited = current.item.clone();
    edited.password = "changed on B".into();
    b.vault.update(edited, &current.revision).unwrap();
    let (report_a, _) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(report_a.applied, 1);
    assert_eq!(report_a.quarantined, 0);
    assert_eq!(
        a.vault.get(&second.id).unwrap().item.password,
        "changed on B"
    );
    assert_eq!(ids(&a.vault), ids(&b.vault));

    // A repeated sync has nothing to send.
    let (report_a, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!((report_a.sent, report_b.sent), (0, 0));

    // The joined vault reopens with its own password.
    drop(b.vault);
    let mut reopened = Vault::open(dir.path().join("b.db")).unwrap();
    assert!(reopened.unlock("inviter password").is_err());
    reopened.unlock("joiner password").unwrap();
    assert_eq!(reopened.list().unwrap().len(), 2);
}

#[test]
fn concurrent_edits_through_sync_converge_on_the_same_conflict() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let item = login("Shared", "original");
    let base = a.vault.put(item.clone()).unwrap().revision;
    let mut b = pair(dir.path(), &mut a);
    sync(&mut a.vault, &mut b.vault);

    for (device, password) in [(&mut a, "from A"), (&mut b, "from B")] {
        let mut changed = item.clone();
        changed.password = password.into();
        device.vault.update(changed, &base).unwrap();
    }
    sync(&mut a.vault, &mut b.vault);
    for vault in [&a.vault, &b.vault] {
        assert!(vault.get(&item.id).unwrap().conflict);
    }
    let heads = |vault: &Vault| -> Vec<String> {
        vault
            .versions(&item.id)
            .unwrap()
            .into_iter()
            .map(|version| version.revision)
            .collect()
    };
    assert_eq!(heads(&a.vault), heads(&b.vault));
}

#[test]
fn interrupted_sync_resumes_with_a_new_session() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    for index in 0..150 {
        a.vault.put(login(&format!("Item {index}"), "p")).unwrap();
    }
    let mut b = pair(dir.path(), &mut a);

    // Cut the connection after the first batch reaches B.
    let mut batches = 0;
    let (complete, _, partial) = run_sync(&mut a.vault, &mut b.vault, |to_b, message| {
        if to_b && matches!(message, SyncMessage::Revisions { .. }) {
            batches += 1;
            if batches == 2 {
                return Fault::Disconnect;
            }
        }
        Fault::Deliver
    })
    .unwrap();
    assert!(!complete);
    assert_eq!(partial.applied, 64);
    assert_eq!(b.vault.list().unwrap().len(), 64);

    let (to_b, _) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 86);
    assert_eq!(ids(&a.vault), ids(&b.vault));
}

#[test]
fn a_missing_parent_is_requested_and_the_child_applied() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let item = login("Chain", "v1");
    let first = a.vault.put(item.clone()).unwrap().revision;
    let mut b = pair(dir.path(), &mut a);
    let mut next = item.clone();
    next.password = "v2".into();
    a.vault.update(next, &first).unwrap();

    // Drop the parent from the first batch; B must ask for it.
    let mut dropped = false;
    let (complete, _, report_b) = run_sync(&mut a.vault, &mut b.vault, |to_b, message| {
        if let (true, SyncMessage::Revisions { revisions }) = (to_b, message) {
            if !dropped {
                dropped = true;
                return Fault::Replace(SyncMessage::Revisions {
                    revisions: revisions
                        .iter()
                        .filter(|revision| revision.revision_id() != first)
                        .cloned()
                        .collect(),
                });
            }
        }
        Fault::Deliver
    })
    .unwrap();
    assert!(complete);
    assert_eq!(report_b.applied, 2);
    assert_eq!(report_b.pending, 0);
    assert_eq!(b.vault.get(&item.id).unwrap().item.password, "v2");
}

#[test]
fn revisions_from_a_device_unknown_to_the_receiver_are_quarantined() {
    let dir = tempdir().unwrap();
    let (vault, recovery) = Vault::create(dir.path().join("a.db"), "inviter password").unwrap();
    let mut a = Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    };
    let item = login("Shared", "original");
    let base = a.vault.put(item.clone()).unwrap().revision;
    let mut b = pair(dir.path(), &mut a);
    sync(&mut a.vault, &mut b.vault);

    // D is a restored copy of A that A trusts but B was never told about.
    a.vault.export_backup(dir.path().join("a.osmbak")).unwrap();
    let mut d = Vault::restore_backup(
        dir.path().join("a.osmbak"),
        dir.path().join("d.db"),
        &recovery,
        "d password",
    )
    .unwrap();
    a.vault
        .authorize_device(d.device_id().unwrap(), d.device_public_key().unwrap())
        .unwrap();
    let mut changed = item.clone();
    changed.password = "from D".into();
    let from_d = d.update(changed, &base).unwrap().revision;
    let revision = d
        .revisions_by_id(std::slice::from_ref(&from_d))
        .unwrap()
        .remove(0);
    a.vault.apply_encrypted_revision(revision).unwrap();

    let (_, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(report_b.quarantined, 1);
    assert_eq!(report_b.applied, 0);
    assert_eq!(b.vault.get(&item.id).unwrap().item.password, "original");
    assert_eq!(b.vault.quarantined().unwrap()[0].revision, from_d);

    // It is offered again by the next session, recognized as already held,
    // and held only once.
    let (_, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!((report_b.duplicates, report_b.quarantined), (1, 0));
    assert_eq!(b.vault.quarantined().unwrap().len(), 1);
}

#[test]
fn a_forged_revision_ends_the_session_without_storing_it() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    a.vault.put(login("Only", "p")).unwrap();
    let mut b = pair(dir.path(), &mut a);
    let result = run_sync(&mut a.vault, &mut b.vault, |to_b, message| {
        if let (true, SyncMessage::Revisions { revisions }) = (to_b, message) {
            let mut forged = revisions.clone();
            forged[0].signature[0] ^= 1;
            return Fault::Replace(SyncMessage::Revisions { revisions: forged });
        }
        Fault::Deliver
    });
    assert!(matches!(
        result,
        Err(Error::InvalidRevision(
            osm_vault_core::Error::InvalidSignature
        ))
    ));
    assert!(b.vault.list().unwrap().is_empty());
}

#[test]
fn sessions_for_different_vaults_are_refused() {
    let dir = tempdir().unwrap();
    let (mut first, _) = Vault::create(dir.path().join("one.db"), "p").unwrap();
    let (mut second, _) = Vault::create(dir.path().join("two.db"), "p").unwrap();
    assert!(matches!(
        run_sync(&mut first, &mut second, |_, _| Fault::Deliver),
        Err(Error::VaultMismatch)
    ));
}

#[test]
fn pairing_rejects_replay_expiry_tampering_and_unconfirmed_codes() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());

    // Expired invitations are refused on both sides.
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        60,
    )
    .unwrap();
    let code = invitation.encode().unwrap();
    assert!(matches!(
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW + 60),
        Err(Error::InvitationExpired)
    ));
    let (_, request) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW + 59).unwrap();
    assert!(matches!(
        review_join(&a.vault, &a.invitations, &mut a.peers, request, NOW + 60),
        Err(Error::Sync(osm_vault_sync::Error::InvitationExpired))
    ));
    assert!(invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        16 * 60
    )
    .is_err());
    assert!(Invitation::decode("OSM-PAIR1-not-base64!").is_err());

    // A request whose signature does not match the key it names.
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        300,
    )
    .unwrap();
    let code = invitation.encode().unwrap();
    let (_, request) = Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let mut forged: JoinRequest = over_wire(&request);
    forged.tamper_signature();
    assert!(matches!(
        review_join(&a.vault, &a.invitations, &mut a.peers, forged, NOW),
        Err(Error::InvalidSignature)
    ));

    // The joiner refuses a grant that was altered in transit, and one the
    // owner did not confirm; no vault file is created either way.
    let (joiner, request) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let review = review_join(&a.vault, &a.invitations, &mut a.peers, request, NOW).unwrap();
    let grant = approve_join(
        &mut a.vault,
        &mut a.invitations,
        &mut a.peers,
        review,
        None,
        NOW,
    )
    .unwrap();
    let mut tampered: JoinGrant = over_wire(&grant);
    tampered.tamper_devices();
    let mut peers = PeerStore::open_in_memory().unwrap();
    let path = dir.path().join("b.db");
    let result = joiner.finish(&tampered, true, &path, "p", &mut peers, NOW);
    assert!(matches!(result, Err(Error::InvalidSignature)));
    assert!(!path.exists());

    // The token was consumed by the approval: it cannot be replayed.
    let (_, replay) = Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    assert!(matches!(
        review_join(&a.vault, &a.invitations, &mut a.peers, replay, NOW),
        Err(Error::Sync(osm_vault_sync::Error::InvitationReplay))
    ));

    // One paired device is the limit until committed membership exists.
    assert!(matches!(
        invite(
            &a.vault,
            &mut a.invitations,
            &mut a.peers,
            address(),
            NOW,
            300
        ),
        Err(Error::PeerLimit)
    ));
}

#[test]
fn the_joiner_requires_owner_confirmation() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        300,
    )
    .unwrap();
    let (joiner, request) = Joiner::start(
        Invitation::decode(&invitation.encode().unwrap()).unwrap(),
        JOINER_PIN,
        NOW,
    )
    .unwrap();
    let review = review_join(&a.vault, &a.invitations, &mut a.peers, request, NOW).unwrap();
    let grant = approve_join(
        &mut a.vault,
        &mut a.invitations,
        &mut a.peers,
        review,
        None,
        NOW,
    )
    .unwrap();
    let path = dir.path().join("b.db");
    let mut peers = PeerStore::open_in_memory().unwrap();
    assert!(matches!(
        joiner.finish(&grant, false, &path, "p", &mut peers, NOW),
        Err(Error::NotConfirmed)
    ));
    assert!(!path.exists());
    assert!(peers.peers().unwrap().is_empty());
}

#[test]
fn oversized_and_malformed_frames_are_rejected() {
    let mut decoder = FrameDecoder::default();
    let declared = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
    assert!(matches!(decoder.push(&declared), Err(Error::FrameTooLarge)));

    let mut decoder = FrameDecoder::default();
    decoder.push(&[0, 0, 0, 3, 0xFF, 0xFF, 0xFF]).unwrap();
    let body = decoder.next_body().unwrap().unwrap();
    assert!(matches!(
        decode_body::<SyncMessage>(&body),
        Err(Error::MalformedFrame)
    ));

    // Trailing bytes after a valid message are rejected too.
    let mut frame = encode_frame(&SyncMessage::Done).unwrap();
    frame.push(0);
    frame[3] += 1;
    let mut decoder = FrameDecoder::default();
    decoder.push(&frame).unwrap();
    let body = decoder.next_body().unwrap().unwrap();
    assert!(matches!(
        decode_body::<SyncMessage>(&body),
        Err(Error::MalformedFrame)
    ));
}

#[test]
fn a_locked_receiver_stages_everything_and_applies_it_after_unlock() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let item = login("Mail", "sent while B is locked");
    a.vault.put(item.clone()).unwrap();
    let mut b = pair(dir.path(), &mut a);

    b.vault.lock();
    let (to_b, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 1);
    assert_eq!(
        (report_b.received, report_b.applied, report_b.pending),
        (1, 0, 1)
    );
    // Nothing was decrypted: B still cannot read, and has only staged it.
    assert!(matches!(
        b.vault.get(&item.id),
        Err(osm_vault_core::Error::Locked)
    ));
    assert!(b.vault.revision_ids().unwrap().is_empty());

    // A second locked session does not resend what B already staged.
    let (to_b, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!((to_b.sent, report_b.received), (0, 0));

    b.vault.unlock("joiner password").unwrap();
    let processed = b.vault.process_staged().unwrap();
    assert_eq!((processed.applied, processed.pending), (1, 0));
    assert_eq!(
        b.vault.get(&item.id).unwrap().item.password,
        "sent while B is locked"
    );
    assert_eq!(ids(&a.vault), ids(&b.vault));
}

#[test]
fn a_locked_device_can_still_send() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    a.vault.put(login("From a locked sender", "p")).unwrap();
    let mut b = pair(dir.path(), &mut a);
    a.vault.lock();
    let (from_a, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!((from_a.sent, report_b.applied), (1, 1));
    assert_eq!(b.vault.list().unwrap().len(), 1);
}

#[test]
fn staged_revisions_are_processed_when_the_next_session_starts_unlocked() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    a.vault.put(login("Later", "p")).unwrap();
    let mut b = pair(dir.path(), &mut a);
    b.vault.lock();
    sync(&mut a.vault, &mut b.vault);
    b.vault.unlock("joiner password").unwrap();
    // No explicit processing: starting a session while unlocked does it.
    let (_, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(
        (report_b.applied, report_b.received, report_b.pending),
        (1, 0, 0)
    );
    assert_eq!(b.vault.list().unwrap().len(), 1);
}
