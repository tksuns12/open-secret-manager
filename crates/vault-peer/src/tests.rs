use std::path::Path;

use osm_vault_core::{Item, PendingDevice, Vault};
use osm_vault_membership::ControlState;
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tempfile::tempdir;

use crate::{
    approve_enrollment, invite, invite_through_relay, review_commit,
    wire::{decode_body, encode_frame, FrameDecoder, MAX_FRAME_BYTES},
    EnrollmentGrant, Error, Invitation, JoinCommit, Joiner, MemberContact, PeerStore, RelayCode,
    SyncMessage, SyncReport, SyncSession, Voting,
};

pub(crate) const NOW: u64 = 1_800_000_000;
/// The sans-IO tests never open a TLS connection, so any pin will do.
pub(crate) const JOINER_PIN: [u8; 32] = [7; 32];

pub(crate) fn address() -> Vec<String> {
    vec!["127.0.0.1:1".to_owned()]
}

pub(crate) struct Device {
    pub(crate) vault: Vault,
    invitations: InvitationStore,
    peers: PeerStore,
}

pub(crate) fn inviter(dir: &Path) -> Device {
    let (vault, _) = Vault::create(dir.join("a.db"), "inviter password").unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    }
}

pub(crate) fn login(title: &str, password: &str) -> Item {
    let mut item = Item::new(title);
    item.username = "owner@example.test".into();
    item.password = password.into();
    item
}

/// Sends a pairing message through the real frame encoding.
pub(crate) fn over_wire<T: serde::Serialize + serde::de::DeserializeOwned>(message: &T) -> T {
    let frame = encode_frame(message).unwrap();
    let mut decoder = FrameDecoder::default();
    decoder.push(&frame).unwrap();
    decode_body(&decoder.next_body().unwrap().unwrap()).unwrap()
}

/// Gives `a`'s vault a second device, as a completed enrollment does: the
/// new device has its own identity, password, and root key, holds the
/// vault's epoch keys, and each device accepts the other's revisions.
pub(crate) fn pair(dir: &Path, a: &mut Device) -> Device {
    let device = PendingDevice::generate();
    let material = a.vault.enrollment_material().unwrap();
    a.vault
        .authorize_device(device.device_id(), device.public_key())
        .unwrap();
    let vault = Vault::join(dir.join("b.db"), "joiner password", device, material).unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    }
}

/// This device as the only member an enrollment grant names.
fn own_contact(device: &mut Device) -> Vec<MemberContact> {
    vec![MemberContact {
        device_id: device.vault.device_id().unwrap(),
        transport_pin: device.peers.transport_identity().unwrap().pin(),
        address: None,
    }]
}

/// What the in-memory transport does to one framed message.
pub(crate) enum Fault {
    Deliver,
    /// Deliver a modified message.
    Replace(SyncMessage),
    /// Cut the connection: nothing more is delivered in either direction.
    Disconnect,
}

/// Moves framed messages between two sessions until both complete, the
/// transport is cut, or a step limit is hit. Returns whether both completed.
pub(crate) fn run_sync(
    a: &mut Vault,
    b: &mut Vault,
    fault: impl FnMut(bool, &SyncMessage) -> Fault,
) -> Result<(bool, SyncReport, SyncReport), Error> {
    run_sync_after(a, b, |_, _| {}, fault)
}

/// As [`run_sync`], with `started` run on both vaults once both sessions
/// have started and before either has received anything.
fn run_sync_after(
    a: &mut Vault,
    b: &mut Vault,
    started: impl FnOnce(&mut Vault, &mut Vault),
    mut fault: impl FnMut(bool, &SyncMessage) -> Fault,
) -> Result<(bool, SyncReport, SyncReport), Error> {
    // (to_b, message)
    let mut queue: std::collections::VecDeque<(bool, Vec<u8>)> = Default::default();
    // What a side sends, in its order, onto the one queue both share.
    let send = |session: &mut SyncSession,
                vault: &Vault,
                to_b: bool,
                queue: &mut std::collections::VecDeque<(bool, Vec<u8>)>|
     -> Result<(), Error> {
        while let Some(message) = session.next_message(vault)? {
            queue.push_back((to_b, encode_frame(&message)?));
        }
        Ok(())
    };
    let mut session_a = SyncSession::start(a, None)?;
    let mut session_b = SyncSession::start(b, None)?;
    send(&mut session_a, a, true, &mut queue)?;
    send(&mut session_b, b, false, &mut queue)?;
    started(a, b);
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
        if to_b {
            session_b.handle(b, message)?;
            send(&mut session_b, b, false, &mut queue)?;
        } else {
            session_a.handle(a, message)?;
            send(&mut session_a, a, true, &mut queue)?;
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

pub(crate) fn sync(a: &mut Vault, b: &mut Vault) -> (SyncReport, SyncReport) {
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

    // B's summary counts it among what B holds, so the next session does
    // not offer it again, and it is held once.
    let (to_b, report_b) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 0);
    assert_eq!((report_b.duplicates, report_b.quarantined), (0, 0));
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
    let (_, commit) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW + 59).unwrap();
    assert!(matches!(
        review_commit(
            &a.vault,
            &a.invitations,
            &mut a.peers,
            commit,
            Voting::Votes,
            None,
            NOW + 60,
        ),
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

    // A commit whose signature does not match the key it names.
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
    let (_, commit) = Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let mut forged: JoinCommit = over_wire(&commit);
    forged.tamper_signature();
    assert!(matches!(
        review_commit(
            &a.vault,
            &a.invitations,
            &mut a.peers,
            forged,
            Voting::Votes,
            None,
            NOW,
        ),
        Err(Error::InvalidSignature)
    ));

    // A tampered relay binding or bad nonce reveal is refused.
    let (_, commit) = Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let mut bad_relay: JoinCommit = over_wire(&commit);
    bad_relay.tamper_relay_binding();
    assert!(matches!(
        review_commit(
            &a.vault,
            &a.invitations,
            &mut a.peers,
            bad_relay,
            Voting::Votes,
            None,
            NOW,
        ),
        Err(Error::ProtocolViolation)
    ));
    let rogue_relay = RelayCode::new("rogue.example.test:47830", [9; 32], [8; 32]).unwrap();
    let relayed_inv = invite_through_relay(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        &rogue_relay,
        NOW,
        300,
    )
    .unwrap();
    let (_, relayed_commit) = Joiner::start(
        Invitation::decode(&relayed_inv.encode().unwrap()).unwrap(),
        JOINER_PIN,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        review_commit(
            &a.vault,
            &a.invitations,
            &mut a.peers,
            relayed_commit,
            Voting::Votes,
            None,
            NOW,
        ),
        Err(Error::ProtocolViolation)
    ));

    // Bad reveal nonce does not match the earlier commitment.
    let (pending, commit) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let (verified, challenge) = review_commit(
        &a.vault,
        &a.invitations,
        &mut a.peers,
        over_wire(&commit),
        Voting::Votes,
        None,
        NOW,
    )
    .unwrap();
    let (_, mut reveal) = pending.accept_challenge(&over_wire(&challenge)).unwrap();
    reveal.tamper_nonce();
    assert!(matches!(
        verified.complete(reveal),
        Err(Error::ProtocolViolation)
    ));

    // Mismatched voting role at approval is refused.
    let (pending, commit) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let (verified, challenge) = review_commit(
        &a.vault,
        &a.invitations,
        &mut a.peers,
        over_wire(&commit),
        Voting::WithoutVote,
        None,
        NOW,
    )
    .unwrap();
    let (_, reveal) = pending.accept_challenge(&over_wire(&challenge)).unwrap();
    let review = verified.complete(over_wire(&reveal)).unwrap();
    let members = own_contact(&mut a);
    assert!(matches!(
        approve_enrollment(
            &a.vault,
            &mut a.invitations,
            review,
            members,
            Voting::Votes,
            Some(47820),
            NOW,
        ),
        Err(Error::ProtocolViolation)
    ));

    // The joiner refuses a grant that was altered in transit: it neither
    // accepts the members it names nor creates a vault.
    let (pending, commit) =
        Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    let (verified, challenge) = review_commit(
        &a.vault,
        &a.invitations,
        &mut a.peers,
        over_wire(&commit),
        Voting::Votes,
        None,
        NOW,
    )
    .unwrap();
    let (joiner, reveal) = pending.accept_challenge(&over_wire(&challenge)).unwrap();
    let review = verified.complete(over_wire(&reveal)).unwrap();
    assert_eq!(review.sas(), joiner.sas());
    let members = own_contact(&mut a);
    let (_, grant) = approve_enrollment(
        &a.vault,
        &mut a.invitations,
        review,
        members,
        Voting::Votes,
        Some(47820),
        NOW,
    )
    .unwrap();
    let grant: EnrollmentGrant = over_wire(&grant);
    let members = joiner.members(&grant).unwrap();
    // The inviter is reached at its pairing host with the port the signed
    // grant names; the pairing port itself closes after pairing.
    assert_eq!(members[0].address.as_deref(), Some("127.0.0.1:47820"));
    let mut tampered: EnrollmentGrant = over_wire(&grant);
    tampered.tamper_members();
    assert!(matches!(
        joiner.members(&tampered),
        Err(Error::InvalidSignature)
    ));
    let path = dir.path().join("b.db");
    let result = joiner.finish_enrollment(&tampered, true, &ControlState::default(), &path, "p");
    assert!(matches!(result, Err(Error::InvalidSignature)));
    assert!(!path.exists());

    // The token was consumed by the approval: it cannot be replayed.
    let (_, replay) = Joiner::start(Invitation::decode(&code).unwrap(), JOINER_PIN, NOW).unwrap();
    assert!(matches!(
        review_commit(
            &a.vault,
            &a.invitations,
            &mut a.peers,
            replay,
            Voting::Votes,
            None,
            NOW,
        ),
        Err(Error::Sync(osm_vault_sync::Error::InvitationReplay))
    ));

    // Any number of devices may be invited.
    assert!(invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        address(),
        NOW,
        300
    )
    .is_ok());
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
    let (pending, commit) = Joiner::start(
        Invitation::decode(&invitation.encode().unwrap()).unwrap(),
        JOINER_PIN,
        NOW,
    )
    .unwrap();
    let (verified, challenge) = review_commit(
        &a.vault,
        &a.invitations,
        &mut a.peers,
        commit,
        Voting::Votes,
        None,
        NOW,
    )
    .unwrap();
    let (joiner, reveal) = pending.accept_challenge(&challenge).unwrap();
    let review = verified.complete(reveal).unwrap();
    let members = own_contact(&mut a);
    let (_, grant) = approve_enrollment(
        &a.vault,
        &mut a.invitations,
        review,
        members,
        Voting::Votes,
        None,
        NOW,
    )
    .unwrap();
    let path = dir.path().join("b.db");
    assert!(matches!(
        joiner.finish_enrollment(&grant, false, &ControlState::default(), &path, "p"),
        Err(Error::NotConfirmed)
    ));
    assert!(!path.exists());
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

/// Each side's messages, in order, by kind.
fn kinds(messages: &[(bool, SyncMessage)], to_b: bool) -> Vec<String> {
    messages
        .iter()
        .filter(|(towards_b, _)| *towards_b == to_b)
        .map(|(_, message)| {
            let kind = format!("{message:?}");
            kind.split('(').next().unwrap().to_owned()
        })
        .collect()
}

/// Runs a sync that delivers everything and keeps what was sent.
fn recorded(a: &mut Vault, b: &mut Vault) -> (SyncReport, SyncReport, Vec<(bool, SyncMessage)>) {
    let mut seen = Vec::new();
    let (complete, report_a, report_b) = run_sync(a, b, |to_b, message| {
        seen.push((to_b, message.clone()));
        Fault::Deliver
    })
    .unwrap();
    assert!(complete);
    (report_a, report_b, seen)
}

#[test]
fn devices_that_hold_the_same_send_only_their_summaries() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    for index in 0..300 {
        a.vault.put(login(&format!("Item {index}"), "p")).unwrap();
    }
    let mut b = pair(dir.path(), &mut a);
    sync(&mut a.vault, &mut b.vault);
    let (_, _, seen) = recorded(&mut a.vault, &mut b.vault);
    for to_b in [true, false] {
        assert_eq!(kinds(&seen, to_b), ["Hello", "Summary", "Done", "Finished"]);
    }
}

#[test]
fn one_new_revision_sends_one_buckets_ids_and_that_revision() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    for index in 0..300 {
        a.vault.put(login(&format!("Item {index}"), "p")).unwrap();
    }
    let mut b = pair(dir.path(), &mut a);
    sync(&mut a.vault, &mut b.vault);
    let new = a.vault.put(login("New", "p")).unwrap().revision;
    let (to_b, to_a, seen) = recorded(&mut a.vault, &mut b.vault);
    assert_eq!((to_b.sent, to_a.sent), (1, 0));
    assert_eq!(
        kinds(&seen, true),
        ["Hello", "Summary", "Ids", "Revisions", "Done", "Finished"]
    );
    assert_eq!(
        kinds(&seen, false),
        ["Hello", "Summary", "Ids", "Done", "Finished"]
    );
    let bucket = u8::from_str_radix(&new[..2], 16).unwrap();
    for (_, message) in &seen {
        if let SyncMessage::Ids { ids } = message {
            assert!(ids.iter().all(|id| id[0] == bucket));
        }
    }
}

#[test]
fn batches_hold_at_most_64_revisions_or_8_mib_and_parents_come_first() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let item = login("Edited", "v0");
    let mut head = a.vault.put(item.clone()).unwrap().revision;
    for index in 0..150 {
        a.vault.put(login(&format!("Item {index}"), "p")).unwrap();
        // Edits of one item, each the child of the one before.
        let mut edited = item.clone();
        edited.password = format!("v{index}");
        head = a.vault.update(edited, &head).unwrap().revision;
    }
    for index in 0..3 {
        let mut large = login(&format!("Large {index}"), "p");
        large.notes = "x".repeat(5 * 1024 * 1024);
        a.vault.put(large).unwrap();
    }
    let mut b = pair(dir.path(), &mut a);
    let (to_b, _, seen) = recorded(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 304);
    let mut order = Vec::new();
    for (_, message) in &seen {
        if let SyncMessage::Revisions { revisions } = message {
            let bytes: usize = revisions
                .iter()
                .map(|revision| revision.ciphertext.len())
                .sum();
            assert!(revisions.len() <= 64);
            assert!(revisions.len() == 1 || bytes <= 8 * 1024 * 1024, "{bytes}");
            order.extend(revisions.iter().map(|revision| revision.revision_id()));
        }
    }
    // In the order A stored them, which puts each parent first.
    assert_eq!(order, a.vault.revision_ids().unwrap());
    assert_eq!(b.vault.get(&item.id).unwrap().item.password, "v149");
}

#[test]
fn a_revision_written_while_a_session_runs_waits_for_the_next() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    a.vault.put(login("Before", "p")).unwrap();
    let mut b = pair(dir.path(), &mut a);
    let mut later = None;
    let (complete, to_b, _) = run_sync_after(
        &mut a.vault,
        &mut b.vault,
        |a, _| later = Some(a.put(login("During", "p")).unwrap().revision),
        |_, _| Fault::Deliver,
    )
    .unwrap();
    assert!(complete);
    assert_eq!(to_b.sent, 1);
    let later = later.unwrap();
    assert!(!ids(&b.vault).contains(&later));
    let (to_b, _) = sync(&mut a.vault, &mut b.vault);
    assert_eq!(to_b.sent, 1);
    assert!(ids(&b.vault).contains(&later));
}

#[test]
fn a_parent_the_peer_cannot_send_is_asked_for_once() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let item = login("Chain", "v1");
    let first = a.vault.put(item.clone()).unwrap().revision;
    let mut next = item.clone();
    next.password = "v2".into();
    a.vault.update(next, &first).unwrap();
    let mut b = pair(dir.path(), &mut a);

    // The parent never arrives, however often it is sent.
    let mut asked = 0;
    let (complete, _, report_b) = run_sync(&mut a.vault, &mut b.vault, |to_b, message| {
        match (to_b, message) {
            (false, SyncMessage::Need { .. }) => asked += 1,
            (true, SyncMessage::Revisions { revisions }) => {
                return Fault::Replace(SyncMessage::Revisions {
                    revisions: revisions
                        .iter()
                        .filter(|revision| revision.revision_id() != first)
                        .cloned()
                        .collect(),
                })
            }
            _ => {}
        }
        Fault::Deliver
    })
    .unwrap();
    assert!(complete);
    assert_eq!(asked, 1);
    assert_eq!(report_b.pending, 1);
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

#[test]
fn a_joined_device_holds_every_epoch_key_under_its_own_root() {
    let dir = tempdir().unwrap();
    let (vault, recovery) = Vault::create(dir.path().join("a.db"), "inviter password").unwrap();
    let mut a = Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    };
    a.vault.put(login("Written in epoch 1", "p")).unwrap();
    let (epoch, _) = a.vault.generate_epoch_key().unwrap();
    a.vault.activate_epoch(epoch).unwrap();
    a.vault.put(login("Written in epoch 2", "p")).unwrap();

    let mut b = pair(dir.path(), &mut a);
    assert_eq!(b.vault.current_epoch(), 2);
    assert_eq!(b.vault.epoch_keys().unwrap().len(), 2);
    sync(&mut a.vault, &mut b.vault);
    assert_eq!(b.vault.list().unwrap().len(), 2);

    // The joiner has its own root, so recovery starts off; the vault's
    // recovery key, checked against the vault's recovery check, turns it on.
    assert!(!b.vault.recovery_enabled());
    b.vault.enable_recovery(&recovery).unwrap();
}
