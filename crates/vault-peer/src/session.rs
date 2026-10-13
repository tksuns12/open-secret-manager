//! One synchronization exchange between two copies of a vault.
//!
//! Both sides open with `Hello` and a `Summary`: a digest of each of 256
//! buckets of the revision IDs they hold, accepted, staged, or held for
//! review (see [`inventory`]). Where the digests of a bucket differ, each
//! side sends its IDs in that bucket, in ascending order and in chunks
//! (`Ids`), and each answers the other's with the revisions it lacks,
//! parents first, in bounded `Revisions` batches followed by `Done`. When
//! no bucket differs, both answer at once with `Done`.
//!
//! Every received revision is first staged durably in the vault's ingress
//! queue, which works while the vault is locked and checks only the
//! envelope's shape. If the vault is unlocked, staged revisions are then
//! verified and applied, each moving out of the queue in the same
//! transaction. A revision whose parent is missing stays staged; after
//! `Done` the receiver asks for missing parents with `Need`, for a bounded
//! number of rounds. When a side needs nothing more it sends `Finished`; the
//! session is complete once both have.
//!
//! The session only queues what it sends; [`SyncSession::next_message`]
//! takes the next message off the queue, reading a batch of revisions from
//! the vault only then, so that a large answer is never held all at once.
//!
//! An interrupted session is resumed by starting a new one: summaries
//! recompute what is missing, and staged revisions are never re-sent.

use std::collections::{HashSet, VecDeque};

use osm_vault_core::{EncryptedRevision, StageOutcome, Vault};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub(crate) mod inventory;

pub use inventory::RevisionId;
use inventory::{Comparison, Differing};

pub const PROTOCOL_VERSION: u16 = 2;
const MAX_BATCH_REVISIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_NEED_ROUNDS: u32 = 8;
/// The most parents asked for in one round; more are asked for in the next.
const MAX_NEED: usize = 65_536;

/// `Hello` comes first, in the form every version has, so that a device of
/// another version reads it and refuses the session by its version.
#[derive(Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    Hello {
        version: u16,
        vault_id: [u8; 32],
        /// The port this device accepts sync connections on, if any. The
        /// peer pairs it with the address the connection came from.
        listen_port: Option<u16>,
    },
    /// The digest of each bucket of the revision IDs this side holds.
    Summary {
        buckets: Vec<[u8; 32]>,
    },
    /// The next chunk of this side's IDs in the buckets that differ.
    Ids {
        ids: Vec<RevisionId>,
    },
    Revisions {
        revisions: Vec<EncryptedRevision>,
    },
    Need {
        ids: Vec<RevisionId>,
    },
    /// Everything the peer lacked or asked for has been sent.
    Done,
    /// This side needs nothing more.
    Finished,
}

impl std::fmt::Debug for SyncMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hello { version, .. } => write!(f, "Hello(v{version})"),
            Self::Summary { buckets } => write!(f, "Summary({})", buckets.len()),
            Self::Ids { ids } => write!(f, "Ids({})", ids.len()),
            Self::Revisions { revisions } => write!(f, "Revisions({})", revisions.len()),
            Self::Need { ids } => write!(f, "Need({})", ids.len()),
            Self::Done => f.write_str("Done"),
            Self::Finished => f.write_str("Finished"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Revisions sent to the peer.
    pub sent: usize,
    /// New revisions received and stored durably (staged).
    pub received: usize,
    /// Revisions received that were already accepted, staged, or held.
    pub duplicates: usize,
    /// Staged revisions verified and merged. Only while unlocked.
    pub applied: usize,
    /// Staged revisions from unauthorized devices, held for owner review.
    pub quarantined: usize,
    /// Revisions still staged when the session ended: everything received
    /// while locked, or revisions waiting for a parent.
    pub pending: usize,
}

/// What waits to be sent, in order.
enum Outgoing {
    Message(SyncMessage),
    /// This side's IDs in the differing buckets, from this one on.
    Ids {
        from: usize,
    },
    /// Stored revisions with the length of each one's ciphertext, parents
    /// first.
    Revisions(VecDeque<(RevisionId, usize)>),
}

pub struct SyncSession {
    vault_id: [u8; 32],
    /// The IDs this side held when the session started, sorted; once the
    /// peer's summary has come, only those in the buckets that differ.
    held: Vec<RevisionId>,
    summary: Vec<[u8; 32]>,
    /// Anything staged before the session is processed once its opening
    /// has gone out, not before.
    processed_staged: bool,
    hello_received: bool,
    peer_listen_port: Option<u16>,
    /// The buckets that differ, once the peer's summary has come.
    differing: Option<Differing>,
    comparison: Comparison,
    /// Rounds in which this side asked for missing parents, and what it
    /// asked for: each parent is asked for once.
    need_rounds: u32,
    asked: HashSet<RevisionId>,
    /// Rounds in which the peer asked for missing parents.
    peer_need_rounds: u32,
    /// The peer's `Done`s, each the end of an answer to this side.
    dones_received: u32,
    sent_finished: bool,
    peer_finished: bool,
    outbox: VecDeque<Outgoing>,
    report: SyncReport,
}

impl SyncSession {
    /// Starts a session with `Hello` and `Summary` waiting to be sent. If
    /// the vault is unlocked, anything staged earlier is processed when the
    /// first message from the peer is handled, after those have gone out.
    pub fn start(vault: &Vault, listen_port: Option<u16>) -> Result<Self> {
        let held = vault.held_revision_ids()?;
        let summary = inventory::summary(&held);
        let vault_id = vault.vault_id();
        let outbox = VecDeque::from([
            Outgoing::Message(SyncMessage::Hello {
                version: PROTOCOL_VERSION,
                vault_id,
                listen_port,
            }),
            Outgoing::Message(SyncMessage::Summary {
                buckets: summary.clone(),
            }),
        ]);
        Ok(Self {
            vault_id,
            held,
            summary,
            processed_staged: false,
            hello_received: false,
            peer_listen_port: None,
            differing: None,
            comparison: Comparison::new(),
            need_rounds: 0,
            asked: HashSet::new(),
            peer_need_rounds: 0,
            dones_received: 0,
            sent_finished: false,
            peer_finished: false,
            outbox,
            report: SyncReport::default(),
        })
    }

    /// Both sides have said they need nothing more. What this side still
    /// has to send is in [`Self::has_outgoing`].
    pub fn is_complete(&self) -> bool {
        self.sent_finished && self.peer_finished
    }

    pub fn has_outgoing(&self) -> bool {
        !self.outbox.is_empty()
    }

    pub fn report(&self) -> &SyncReport {
        &self.report
    }

    /// The port the peer said it listens on, once its `Hello` arrived.
    pub fn peer_listen_port(&self) -> Option<u16> {
        self.peer_listen_port
    }

    /// The next message to send, if any. A batch of revisions is read from
    /// the vault here, which works while it is locked.
    pub fn next_message(&mut self, vault: &Vault) -> Result<Option<SyncMessage>> {
        loop {
            let Some(next) = self.outbox.front_mut() else {
                return Ok(None);
            };
            match next {
                Outgoing::Message(_) => {
                    let Some(Outgoing::Message(message)) = self.outbox.pop_front() else {
                        unreachable!()
                    };
                    return Ok(Some(message));
                }
                Outgoing::Ids { from } => {
                    let (chunk, last) = inventory::chunk(&self.held, *from);
                    let ids = chunk.to_vec();
                    *from += ids.len();
                    if last {
                        self.outbox.pop_front();
                    }
                    return Ok(Some(SyncMessage::Ids { ids }));
                }
                Outgoing::Revisions(queued) => {
                    let mut batch = Vec::new();
                    let mut bytes = 0;
                    while let Some((id, size)) = queued.front() {
                        if !batch.is_empty()
                            && (batch.len() == MAX_BATCH_REVISIONS
                                || bytes + size > MAX_BATCH_BYTES)
                        {
                            break;
                        }
                        bytes += size;
                        batch.push(inventory::to_hex(id));
                        queued.pop_front();
                    }
                    if queued.is_empty() {
                        self.outbox.pop_front();
                    }
                    // `revisions_by_id` returns them in the order stored.
                    let revisions = vault.revisions_by_id(&batch)?;
                    if revisions.is_empty() {
                        continue;
                    }
                    self.report.sent += revisions.len();
                    return Ok(Some(SyncMessage::Revisions { revisions }));
                }
            }
        }
    }

    /// Handles one message from the peer, queueing any answer.
    pub fn handle(&mut self, vault: &mut Vault, message: SyncMessage) -> Result<()> {
        if !self.processed_staged {
            self.processed_staged = true;
            self.process(vault)?;
        }
        match message {
            SyncMessage::Hello {
                version,
                vault_id,
                listen_port,
            } => {
                if self.hello_received {
                    return Err(Error::ProtocolViolation);
                }
                if version != PROTOCOL_VERSION {
                    return Err(Error::UnsupportedVersion);
                }
                if vault_id != self.vault_id {
                    return Err(Error::VaultMismatch);
                }
                self.hello_received = true;
                self.peer_listen_port = listen_port.filter(|port| *port != 0);
                Ok(())
            }
            _ if !self.hello_received => Err(Error::ProtocolViolation),
            SyncMessage::Summary { buckets } => {
                // A peer sends its summary once; again would have this side
                // send its IDs again.
                if self.differing.is_some() {
                    return Err(Error::ProtocolViolation);
                }
                let differing =
                    Differing::between(&self.summary, &buckets).ok_or(Error::ProtocolViolation)?;
                self.held.retain(|id| differing.contains(id));
                if differing.is_empty() {
                    self.outbox.push_back(Outgoing::Message(SyncMessage::Done));
                } else {
                    self.outbox.push_back(Outgoing::Ids { from: 0 });
                }
                self.differing = Some(differing);
                Ok(())
            }
            _ if self.differing.is_none() => Err(Error::ProtocolViolation),
            SyncMessage::Ids { ids } => {
                let differing = self.differing.as_ref().expect("checked above");
                if differing.is_empty() {
                    return Err(Error::ProtocolViolation);
                }
                let last = self
                    .comparison
                    .take(differing, &self.held, &ids)
                    .map_err(|_| Error::ProtocolViolation)?;
                if last {
                    let lacking = self.comparison.take_lacking();
                    self.answer(vault, &lacking)?;
                }
                Ok(())
            }
            // The peer answers this side's IDs, or its summary when no
            // bucket differs, and asks for missing parents, only once it has
            // sent all of its own IDs.
            _ if !self.compared() => Err(Error::ProtocolViolation),
            SyncMessage::Need { ids } => {
                // A peer asks for missing parents in as many rounds as the
                // protocol has, as this side does.
                self.peer_need_rounds += 1;
                if self.peer_need_rounds > MAX_NEED_ROUNDS || ids.len() > MAX_NEED {
                    return Err(Error::ProtocolViolation);
                }
                self.answer(vault, &ids)
            }
            SyncMessage::Revisions { revisions } => {
                if revisions.len() > MAX_BATCH_REVISIONS {
                    return Err(Error::ProtocolViolation);
                }
                for revision in revisions {
                    self.stage(vault, revision)?;
                }
                self.process(vault)
            }
            SyncMessage::Done => {
                // One for the answer to this side's IDs, and one for each
                // round in which this side asked for missing parents.
                self.dones_received += 1;
                if self.dones_received > self.need_rounds + 1 {
                    return Err(Error::ProtocolViolation);
                }
                self.after_done(vault)
            }
            SyncMessage::Finished => {
                if self.peer_finished {
                    return Err(Error::ProtocolViolation);
                }
                self.peer_finished = true;
                Ok(())
            }
        }
    }

    /// Whether all of the peer's IDs have come, or none were to come.
    fn compared(&self) -> bool {
        self.differing
            .as_ref()
            .is_some_and(|differing| differing.is_empty() || self.comparison.is_finished())
    }

    /// Queues the stored revisions among `ids`, parents first, and `Done`.
    fn answer(&mut self, vault: &Vault, ids: &[RevisionId]) -> Result<()> {
        let stored = vault.stored_revision_sizes(ids)?;
        if !stored.is_empty() {
            self.outbox
                .push_back(Outgoing::Revisions(stored.into_iter().collect()));
        }
        self.outbox.push_back(Outgoing::Message(SyncMessage::Done));
        Ok(())
    }

    /// Stores a received revision durably before anything else happens to
    /// it. A malformed envelope ends the session.
    fn stage(&mut self, vault: &mut Vault, revision: EncryptedRevision) -> Result<()> {
        match vault.stage_revision(revision) {
            Ok(StageOutcome::Staged) => self.report.received += 1,
            Ok(StageOutcome::Duplicate) => self.report.duplicates += 1,
            Err(
                error @ (osm_vault_core::Error::IngressFull
                | osm_vault_core::Error::Database(_)
                | osm_vault_core::Error::Io(_)
                | osm_vault_core::Error::Locked),
            ) => return Err(Error::Vault(error)),
            Err(error) => return Err(Error::InvalidRevision(error)),
        }
        Ok(())
    }

    /// Verifies and applies staged revisions when the vault is unlocked. A
    /// revision that fails verification was sent by a misbehaving peer: it
    /// is discarded and the session ends.
    fn process(&mut self, vault: &mut Vault) -> Result<()> {
        if !vault.is_unlocked() {
            return Ok(());
        }
        let processed = vault.process_staged()?;
        self.report.applied += processed.applied;
        self.report.quarantined += processed.quarantined;
        if processed.rejected > 0 {
            return Err(Error::InvalidRevision(
                processed
                    .first_rejection
                    .unwrap_or(osm_vault_core::Error::Crypto),
            ));
        }
        Ok(())
    }

    fn after_done(&mut self, vault: &mut Vault) -> Result<()> {
        self.process(vault)?;
        if self.need_rounds < MAX_NEED_ROUNDS {
            // Each parent is asked for once: one the peer could not send,
            // such as one it holds only staged, is not asked for again in
            // place of the others.
            let missing: Vec<RevisionId> = vault
                .staged_missing_parents()?
                .iter()
                .filter_map(|id| inventory::from_hex(id))
                .filter(|id| !self.asked.contains(id))
                .take(MAX_NEED)
                .collect();
            if !missing.is_empty() {
                self.need_rounds += 1;
                self.asked.extend(missing.iter().copied());
                self.outbox
                    .push_back(Outgoing::Message(SyncMessage::Need { ids: missing }));
                return Ok(());
            }
        }
        if self.sent_finished {
            return Ok(());
        }
        self.report.pending = vault.staged_revision_ids()?.len();
        self.sent_finished = true;
        self.outbox
            .push_back(Outgoing::Message(SyncMessage::Finished));
        Ok(())
    }
}

#[cfg(test)]
mod fixtures;
