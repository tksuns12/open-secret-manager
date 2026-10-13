//! What two devices hold, compared without either sending all of it.
//!
//! Revision IDs are SHA-256 digests, so their first byte spreads them
//! evenly over 256 buckets. Each side sends a digest of each bucket; only
//! the IDs in the buckets whose digests differ are then sent, in ascending
//! order and in chunks of [`IDS_PER_CHUNK`], and each side compares them
//! with its own as they arrive, without holding the peer's.

use sha2::{Digest, Sha256};

/// A revision ID as its 32 bytes.
pub type RevisionId = [u8; 32];

pub(crate) const BUCKETS: usize = 256;
/// IDs in each chunk but the last, which holds fewer, so that one list is
/// sent in one way only. A list of a whole number of chunks ends with an
/// empty one.
pub(crate) const IDS_PER_CHUNK: usize = 8_192;
/// The most IDs taken from a peer in one session.
pub(crate) const MAX_PEER_IDS: usize = 1 << 24;
const BUCKET_LABEL: &[u8] = b"osm-sync-bucket-v2\0";

/// The digest of each bucket of `held`, which is sorted and has no repeats:
/// SHA-256 of the label and the bucket's IDs in order.
pub(crate) fn summary(held: &[RevisionId]) -> Vec<[u8; 32]> {
    let mut buckets: Vec<Sha256> = (0..BUCKETS)
        .map(|_| Sha256::new_with_prefix(BUCKET_LABEL))
        .collect();
    for id in held {
        buckets[usize::from(id[0])].update(id);
    }
    buckets
        .into_iter()
        .map(|bucket| bucket.finalize().into())
        .collect()
}

/// The buckets whose digests differ between two summaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Differing([bool; BUCKETS]);

impl Differing {
    /// `None` unless the peer's summary has exactly one digest per bucket.
    pub(crate) fn between(ours: &[[u8; 32]], theirs: &[[u8; 32]]) -> Option<Self> {
        if ours.len() != BUCKETS || theirs.len() != BUCKETS {
            return None;
        }
        let mut differing = [false; BUCKETS];
        for (bucket, (ours, theirs)) in differing.iter_mut().zip(ours.iter().zip(theirs)) {
            *bucket = ours != theirs;
        }
        Some(Self(differing))
    }

    pub(crate) fn contains(&self, id: &RevisionId) -> bool {
        self.0[usize::from(id[0])]
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.0.contains(&true)
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.0.iter().filter(|differs| **differs).count()
    }
}

/// The chunk of `ids` that starts at `from`, and whether it is the last.
pub(crate) fn chunk(ids: &[RevisionId], from: usize) -> (&[RevisionId], bool) {
    let chunk = &ids[from.min(ids.len())..ids.len().min(from + IDS_PER_CHUNK)];
    (chunk, chunk.len() < IDS_PER_CHUNK)
}

/// Why a peer's IDs were refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;

/// Compares the peer's IDs in the differing buckets, chunk by chunk, with
/// `ours`, this device's IDs in those buckets, sorted, and keeps the ones
/// the peer lacks.
#[derive(Debug)]
pub(crate) struct Comparison {
    /// How many of ours have been compared.
    at: usize,
    /// The peer's greatest ID so far.
    last: Option<RevisionId>,
    received: usize,
    limit: usize,
    lacking: Vec<RevisionId>,
    finished: bool,
}

impl Comparison {
    pub(crate) fn new() -> Self {
        Self {
            at: 0,
            last: None,
            received: 0,
            limit: MAX_PEER_IDS,
            lacking: Vec::new(),
            finished: false,
        }
    }

    /// Takes the peer's next chunk and returns whether it was the last.
    /// The peer's IDs must ascend across chunks and lie in `differing`.
    pub(crate) fn take(
        &mut self,
        differing: &Differing,
        ours: &[RevisionId],
        chunk: &[RevisionId],
    ) -> Result<bool, Refused> {
        if self.finished || chunk.len() > IDS_PER_CHUNK {
            return Err(Refused);
        }
        self.received += chunk.len();
        if self.received > self.limit {
            return Err(Refused);
        }
        for id in chunk {
            if !differing.contains(id) || self.last.is_some_and(|last| *id <= last) {
                return Err(Refused);
            }
            self.last = Some(*id);
            while ours.get(self.at).is_some_and(|own| own < id) {
                self.lacking.push(ours[self.at]);
                self.at += 1;
            }
            if ours.get(self.at) == Some(id) {
                self.at += 1;
            }
        }
        if chunk.len() == IDS_PER_CHUNK {
            return Ok(false);
        }
        self.lacking
            .extend_from_slice(&ours[self.at.min(ours.len())..]);
        self.at = ours.len();
        self.finished = true;
        Ok(true)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished
    }

    /// Ours that the peer lacks, once its last chunk has been taken.
    pub(crate) fn take_lacking(&mut self) -> Vec<RevisionId> {
        std::mem::take(&mut self.lacking)
    }
}

pub(crate) fn to_hex(id: &RevisionId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in id {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

/// A revision ID in the vault's form, 64 lowercase hex digits, as bytes.
pub(crate) fn from_hex(text: &str) -> Option<RevisionId> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    if text.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (byte, pair) in id.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(id)
}

#[cfg(test)]
mod tests;
