//! One synchronization exchange between two copies of a vault.
//!
//! Both sides open with `Hello` and an `Inventory` of every revision ID they
//! hold. Each answers the other's inventory with the revisions it lacks,
//! parents first, in bounded `Revisions` batches followed by `Done`. A
//! revision whose parent did not arrive is deferred; after `Done` the
//! receiver asks for missing parents with `Need`, for a bounded number of
//! rounds. When a side needs nothing more it sends `Finished`; the session
//! is complete once both have.
//!
//! The exchange is stateless across sessions: an interrupted session is
//! resumed by starting a new one, since inventories recompute what is
//! missing.

use std::collections::{BTreeSet, HashSet};

use osm_vault_core::{EncryptedRevision, Vault};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const PROTOCOL_VERSION: u16 = 1;
const MAX_INVENTORY: usize = 1_000_000;
const MAX_BATCH_REVISIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_NEED_ROUNDS: u32 = 8;

#[derive(Serialize, Deserialize)]
pub enum SyncMessage {
    Hello {
        version: u16,
        vault_id: [u8; 32],
    },
    Inventory {
        revisions: Vec<String>,
    },
    Revisions {
        revisions: Vec<EncryptedRevision>,
    },
    Need {
        revisions: Vec<String>,
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
            Self::Inventory { revisions } => write!(f, "Inventory({})", revisions.len()),
            Self::Revisions { revisions } => write!(f, "Revisions({})", revisions.len()),
            Self::Need { revisions } => write!(f, "Need({})", revisions.len()),
            Self::Done => f.write_str("Done"),
            Self::Finished => f.write_str("Finished"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Revisions sent to the peer.
    pub sent: usize,
    /// Revisions received and merged.
    pub applied: usize,
    /// Revisions received that were already stored.
    pub duplicates: usize,
    /// Revisions from unauthorized devices, held for owner review.
    pub quarantined: usize,
    /// Revisions still waiting for a parent when the session ended; they are
    /// not stored and will be offered again by the next session.
    pub deferred: usize,
}

pub struct SyncSession {
    vault_id: [u8; 32],
    hello_received: bool,
    deferred: Vec<EncryptedRevision>,
    need_rounds: u32,
    sent_finished: bool,
    peer_finished: bool,
    report: SyncReport,
}

impl SyncSession {
    /// Starts a session and returns the opening messages.
    pub fn start(vault: &Vault) -> Result<(Self, Vec<SyncMessage>)> {
        let session = Self {
            vault_id: vault.vault_id(),
            hello_received: false,
            deferred: Vec::new(),
            need_rounds: 0,
            sent_finished: false,
            peer_finished: false,
            report: SyncReport::default(),
        };
        let opening = vec![
            SyncMessage::Hello {
                version: PROTOCOL_VERSION,
                vault_id: session.vault_id,
            },
            SyncMessage::Inventory {
                revisions: vault.revision_ids()?,
            },
        ];
        Ok((session, opening))
    }

    pub fn is_complete(&self) -> bool {
        self.sent_finished && self.peer_finished
    }

    pub fn report(&self) -> &SyncReport {
        &self.report
    }

    /// Handles one message from the peer and returns the replies to send.
    pub fn handle(&mut self, vault: &mut Vault, message: SyncMessage) -> Result<Vec<SyncMessage>> {
        match message {
            SyncMessage::Hello { version, vault_id } => {
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
                Ok(Vec::new())
            }
            _ if !self.hello_received => Err(Error::ProtocolViolation),
            SyncMessage::Inventory { revisions } => {
                if revisions.len() > MAX_INVENTORY {
                    return Err(Error::ProtocolViolation);
                }
                let theirs: HashSet<String> = revisions.into_iter().collect();
                let missing: Vec<String> = vault
                    .revision_ids()?
                    .into_iter()
                    .filter(|id| !theirs.contains(id))
                    .collect();
                self.send_revisions(vault, &missing)
            }
            SyncMessage::Need { revisions } => {
                if revisions.len() > MAX_INVENTORY {
                    return Err(Error::ProtocolViolation);
                }
                self.send_revisions(vault, &revisions)
            }
            SyncMessage::Revisions { revisions } => {
                if revisions.len() > MAX_BATCH_REVISIONS {
                    return Err(Error::ProtocolViolation);
                }
                for revision in revisions {
                    self.receive(vault, revision)?;
                }
                self.retry_deferred(vault)?;
                Ok(Vec::new())
            }
            SyncMessage::Done => self.after_done(vault),
            SyncMessage::Finished => {
                if self.peer_finished {
                    return Err(Error::ProtocolViolation);
                }
                self.peer_finished = true;
                Ok(Vec::new())
            }
        }
    }

    fn send_revisions(&mut self, vault: &Vault, ids: &[String]) -> Result<Vec<SyncMessage>> {
        let mut messages = Vec::new();
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        // `revisions_by_id` returns parents before children.
        for revision in vault.revisions_by_id(ids)? {
            let size = revision.ciphertext.len();
            if !batch.is_empty()
                && (batch.len() == MAX_BATCH_REVISIONS || batch_bytes + size > MAX_BATCH_BYTES)
            {
                messages.push(SyncMessage::Revisions {
                    revisions: std::mem::take(&mut batch),
                });
                batch_bytes = 0;
            }
            batch_bytes += size;
            batch.push(revision);
            self.report.sent += 1;
        }
        if !batch.is_empty() {
            messages.push(SyncMessage::Revisions { revisions: batch });
        }
        messages.push(SyncMessage::Done);
        Ok(messages)
    }

    fn receive(&mut self, vault: &mut Vault, revision: EncryptedRevision) -> Result<()> {
        let id = revision.revision_id();
        if !vault.revisions_by_id(std::slice::from_ref(&id))?.is_empty() {
            self.report.duplicates += 1;
            return Ok(());
        }
        match vault.apply_encrypted_revision(revision.clone()) {
            Ok(_) => self.report.applied += 1,
            Err(osm_vault_core::Error::Quarantined) => self.report.quarantined += 1,
            Err(osm_vault_core::Error::MissingParent) => self.deferred.push(revision),
            // A forged, malformed, or cross-item revision ends the session;
            // the core has not stored it.
            Err(error) => return Err(Error::InvalidRevision(error)),
        }
        Ok(())
    }

    /// Applies deferred revisions whose parents have since arrived, until no
    /// further progress is possible.
    fn retry_deferred(&mut self, vault: &mut Vault) -> Result<()> {
        loop {
            let pending = std::mem::take(&mut self.deferred);
            let before = pending.len();
            for revision in pending {
                self.receive(vault, revision)?;
            }
            if self.deferred.is_empty() || self.deferred.len() == before {
                return Ok(());
            }
        }
    }

    fn after_done(&mut self, vault: &mut Vault) -> Result<Vec<SyncMessage>> {
        self.retry_deferred(vault)?;
        if !self.deferred.is_empty() && self.need_rounds < MAX_NEED_ROUNDS {
            self.need_rounds += 1;
            let stored: HashSet<String> = vault.revision_ids()?.into_iter().collect();
            let deferred: HashSet<String> = self
                .deferred
                .iter()
                .map(EncryptedRevision::revision_id)
                .collect();
            let missing: BTreeSet<String> = self
                .deferred
                .iter()
                .flat_map(|revision| revision.parents.iter())
                .filter(|parent| !stored.contains(*parent) && !deferred.contains(*parent))
                .cloned()
                .collect();
            if !missing.is_empty() {
                return Ok(vec![SyncMessage::Need {
                    revisions: missing.into_iter().collect(),
                }]);
            }
        }
        if self.sent_finished {
            return Ok(Vec::new());
        }
        self.report.deferred = self.deferred.len();
        self.sent_finished = true;
        Ok(vec![SyncMessage::Finished])
    }
}
