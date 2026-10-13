//! Comparing what two devices hold, without a vault: what is found missing
//! is exactly the difference, a peer's IDs are taken only in their one
//! form, and no message grows with the size of the vault.

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use crate::{wire::encode_frame, SyncMessage};

/// `count` IDs that look like digests, the same for the same `seed`.
fn ids(seed: u64, count: usize) -> Vec<RevisionId> {
    let mut state = seed;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let mut made: Vec<RevisionId> = (0..count)
        .map(|_| {
            let mut id = [0u8; 32];
            for part in id.chunks_mut(8) {
                part.copy_from_slice(&next().to_be_bytes());
            }
            id
        })
        .collect();
    made.sort_unstable();
    made.dedup();
    made
}

/// The chunks a side sends of `held` once `differing` is known, as the
/// session sends them.
fn chunks(differing: &Differing, held: &[RevisionId]) -> Vec<Vec<RevisionId>> {
    let held: Vec<RevisionId> = held
        .iter()
        .filter(|id| differing.contains(id))
        .copied()
        .collect();
    let mut sent = Vec::new();
    let mut from = 0;
    loop {
        let (chunk, last) = chunk(&held, from);
        from += chunk.len();
        sent.push(chunk.to_vec());
        if last {
            return sent;
        }
    }
}

/// What `ours` finds the peer lacks from the peer's chunks of `theirs`.
fn lacking(ours: &[RevisionId], theirs: &[RevisionId]) -> Vec<RevisionId> {
    let differing = Differing::between(&summary(ours), &summary(theirs)).unwrap();
    if differing.is_empty() {
        return Vec::new();
    }
    let ours: Vec<RevisionId> = ours
        .iter()
        .filter(|id| differing.contains(id))
        .copied()
        .collect();
    let mut comparison = Comparison::new();
    let sent = chunks(&differing, theirs);
    for (index, chunk) in sent.iter().enumerate() {
        let last = comparison.take(&differing, &ours, chunk).unwrap();
        assert_eq!(last, index + 1 == sent.len());
    }
    comparison.take_lacking()
}

fn difference(ours: &[RevisionId], theirs: &[RevisionId]) -> Vec<RevisionId> {
    let theirs: BTreeSet<_> = theirs.iter().collect();
    ours.iter()
        .filter(|id| !theirs.contains(id))
        .copied()
        .collect()
}

proptest! {
    /// Whatever each side holds, what one finds the other lacks is what it
    /// holds and the other does not.
    #[test]
    fn what_is_found_missing_is_the_difference(
        shared in 0_usize..200,
        only_ours in 0_usize..40,
        only_theirs in 0_usize..40,
        seed in any::<u64>(),
    ) {
        let common = ids(seed, shared);
        let ours: Vec<RevisionId> = [common.clone(), ids(seed ^ 1, only_ours)].concat().into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        let theirs: Vec<RevisionId> = [common, ids(seed ^ 2, only_theirs)].concat().into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        prop_assert_eq!(lacking(&ours, &theirs), difference(&ours, &theirs));
        prop_assert_eq!(lacking(&theirs, &ours), difference(&theirs, &ours));
    }
}

#[test]
fn what_is_found_missing_is_the_difference_across_many_chunks() {
    // Every ID in one bucket, so that the peer's list is several chunks.
    let narrow = |seed, count| -> Vec<RevisionId> {
        let mut made: Vec<RevisionId> = ids(seed, count)
            .into_iter()
            .map(|mut id| {
                id[0] = 7;
                id
            })
            .collect();
        made.sort_unstable();
        made.dedup();
        made
    };
    let common = narrow(1, 3 * IDS_PER_CHUNK);
    for (ours, theirs) in [
        // A whole number of chunks, so the last is empty.
        (Vec::new(), narrow(2, 2 * IDS_PER_CHUNK)),
        ([common.clone(), narrow(3, 500)].concat(), common.clone()),
        (common.clone(), [common.clone(), narrow(4, 5_000)].concat()),
    ] {
        let mut ours = ours;
        ours.sort_unstable();
        let mut theirs = theirs;
        theirs.sort_unstable();
        assert_eq!(lacking(&ours, &theirs), difference(&ours, &theirs));
        assert_eq!(lacking(&theirs, &ours), difference(&theirs, &ours));
    }
    let differing =
        Differing::between(&summary(&[]), &summary(&narrow(2, 2 * IDS_PER_CHUNK))).unwrap();
    let sent = chunks(&differing, &narrow(2, 2 * IDS_PER_CHUNK));
    assert_eq!(
        sent.iter().map(Vec::len).collect::<Vec<_>>(),
        [IDS_PER_CHUNK, IDS_PER_CHUNK, 0]
    );
}

#[test]
fn a_summary_has_a_digest_for_each_bucket_and_no_other() {
    let held = ids(5, 1_000);
    let ours = summary(&held);
    assert_eq!(ours.len(), BUCKETS);
    for wrong in [BUCKETS - 1, BUCKETS + 1, 0] {
        let theirs = vec![[0u8; 32]; wrong];
        assert!(Differing::between(&ours, &theirs).is_none());
    }
    // The same IDs give the same digests; one more changes one bucket.
    assert!(Differing::between(&ours, &summary(&held))
        .unwrap()
        .is_empty());
    let mut more = held.clone();
    more.push([0xff; 32]);
    more.sort_unstable();
    let differing = Differing::between(&ours, &summary(&more)).unwrap();
    assert_eq!(differing.count(), 1);
    assert!(differing.contains(&[0xff; 32]));
}

#[test]
fn a_peers_ids_are_taken_only_in_their_one_form() {
    let differing = Differing::between(&summary(&[]), &summary(&[[1; 32], [2; 32]])).unwrap();
    let take = |chunks: &[Vec<RevisionId>]| {
        let mut comparison = Comparison::new();
        chunks
            .iter()
            .map(|chunk| comparison.take(&differing, &[], chunk))
            .collect::<Vec<_>>()
    };
    let refused = |chunks: &[Vec<RevisionId>]| take(chunks).contains(&Err(Refused));
    assert_eq!(take(&[vec![[1; 32], [2; 32]]]), [Ok(true)]);
    // Out of order, twice, or outside the buckets that differ.
    assert!(refused(&[vec![[2; 32], [1; 32]]]));
    assert!(refused(&[vec![[1; 32], [1; 32]]]));
    assert!(refused(&[vec![[1; 32], [3; 32]]]));
    // Anything after the last chunk, which is the first one that is not full.
    assert!(refused(&[vec![[1; 32]], vec![[2; 32]]]));
    assert!(refused(&[Vec::new(), Vec::new()]));
    // More than a chunk at once.
    let wide = Differing([true; BUCKETS]);
    let mut comparison = Comparison::new();
    assert_eq!(
        comparison.take(&wide, &[], &ids(6, IDS_PER_CHUNK + 1)),
        Err(Refused)
    );
    // Out of order across chunks.
    let full = ids(7, IDS_PER_CHUNK);
    let mut comparison = Comparison::new();
    assert_eq!(comparison.take(&wide, &[], &full), Ok(false));
    assert_eq!(comparison.take(&wide, &[], &[full[0]]), Err(Refused));
    // More than the bound in all.
    let mut comparison = Comparison {
        limit: IDS_PER_CHUNK + 10,
        ..Comparison::new()
    };
    assert_eq!(
        comparison.take(&wide, &[], &ids(8, IDS_PER_CHUNK)),
        Ok(false)
    );
    let mut over = ids(9, 11);
    over.iter_mut().for_each(|id| id[0] = 0xff);
    over.sort_unstable();
    assert_eq!(comparison.take(&wide, &[], &over), Err(Refused));
}

/// Version 1 sent every ID in one message, which a vault of 387,167
/// revisions or more could not fit in a frame. Now the largest message
/// before revisions are sent is a chunk of IDs or a request for parents,
/// whatever the size of the vault, and when one revision is new the IDs
/// sent are those of one bucket.
#[test]
fn no_message_grows_with_the_vault() {
    let largest_chunk = encode_frame(&SyncMessage::Ids {
        ids: vec![[0xff; 32]; IDS_PER_CHUNK],
    })
    .unwrap()
    .len();
    assert!(largest_chunk <= 256 * 1024 + 8, "{largest_chunk}");
    let largest_need = encode_frame(&SyncMessage::Need {
        ids: vec![[0xff; 32]; 65_536],
    })
    .unwrap()
    .len();
    assert!(largest_need <= 2 * 1024 * 1024 + 8, "{largest_need}");
    for count in [400_000, 1_000_000] {
        let held = ids(10, count);
        let ours = summary(&held);
        let opening = encode_frame(&SyncMessage::Summary {
            buckets: ours.clone(),
        })
        .unwrap()
        .len();
        assert!(opening <= 8 * 1024 + 8, "{opening}");

        // A new device: every ID is sent, a chunk at a time.
        let differing = Differing::between(&ours, &summary(&[])).unwrap();
        assert_eq!(differing.count(), BUCKETS);
        let sent = chunks(&differing, &held);
        assert_eq!(sent.len(), count / IDS_PER_CHUNK + 1);
        assert!(sent.iter().all(|chunk| chunk.len() <= IDS_PER_CHUNK));

        // One revision more on the other side: one bucket, both ways.
        let mut theirs = held.clone();
        theirs.push([0x42; 32]);
        theirs.sort_unstable();
        let differing = Differing::between(&ours, &summary(&theirs)).unwrap();
        assert_eq!(differing.count(), 1);
        let bytes: usize = [&held, &theirs]
            .iter()
            .flat_map(|side| chunks(&differing, side))
            .map(|chunk| {
                encode_frame(&SyncMessage::Ids { ids: chunk })
                    .unwrap()
                    .len()
            })
            .sum();
        // About 2 × count / 256 IDs of 32 bytes, with room for an uneven
        // bucket.
        assert!(
            bytes < 2 * count / BUCKETS * 32 * 12 / 10,
            "{bytes} for {count}"
        );
        assert_eq!(lacking(&theirs, &held), vec![[0x42; 32]]);
    }
}

#[test]
fn ids_are_written_as_the_vault_writes_them() {
    let id: RevisionId = std::array::from_fn(|index| (index * 9) as u8);
    let text = to_hex(&id);
    assert_eq!(text.len(), 64);
    assert_eq!(from_hex(&text), Some(id));
    assert_eq!(from_hex(&text.to_uppercase()), None);
    assert_eq!(from_hex(&text[..62]), None);
    assert_eq!(from_hex(&format!("{}g", &text[..63])), None);
}
