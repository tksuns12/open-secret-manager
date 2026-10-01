//! One synchronization exchange between two copies of a vault.
//!
//! Both sides open with `Hello` and an `Inventory` of every revision ID they
//! hold, accepted or staged. Each answers the other's inventory with the
//! revisions it lacks, parents first, in bounded `Revisions` batches followed
//! by `Done`.
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
//! An interrupted session is resumed by starting a new one: inventories
//! recompute what is missing, and staged revisions are never re-sent.

use std::collections::HashSet;

use osm_vault_core::{EncryptedRevision, StageOutcome, Vault};
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
        /// The port this device accepts sync connections on, if any. The
        /// peer pairs it with the address the connection came from.
        listen_port: Option<u16>,
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

pub struct SyncSession {
    vault_id: [u8; 32],
    hello_received: bool,
    peer_listen_port: Option<u16>,
    need_rounds: u32,
    sent_finished: bool,
    peer_finished: bool,
    report: SyncReport,
}

impl SyncSession {
    /// Starts a session and returns the opening messages. If the vault is
    /// unlocked, anything staged earlier is processed first.
    pub fn start(vault: &mut Vault, listen_port: Option<u16>) -> Result<(Self, Vec<SyncMessage>)> {
        let mut session = Self {
            vault_id: vault.vault_id(),
            hello_received: false,
            peer_listen_port: None,
            need_rounds: 0,
            sent_finished: false,
            peer_finished: false,
            report: SyncReport::default(),
        };
        session.process(vault)?;
        let mut inventory = vault.revision_ids()?;
        inventory.extend(vault.staged_revision_ids()?);
        let opening = vec![
            SyncMessage::Hello {
                version: PROTOCOL_VERSION,
                vault_id: session.vault_id,
                listen_port,
            },
            SyncMessage::Inventory {
                revisions: inventory,
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

    /// The port the peer said it listens on, once its `Hello` arrived.
    pub fn peer_listen_port(&self) -> Option<u16> {
        self.peer_listen_port
    }

    /// Handles one message from the peer and returns the replies to send.
    pub fn handle(&mut self, vault: &mut Vault, message: SyncMessage) -> Result<Vec<SyncMessage>> {
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
                    self.stage(vault, revision)?;
                }
                self.process(vault)?;
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

    fn after_done(&mut self, vault: &mut Vault) -> Result<Vec<SyncMessage>> {
        self.process(vault)?;
        let missing = vault.staged_missing_parents()?;
        if !missing.is_empty() && self.need_rounds < MAX_NEED_ROUNDS {
            self.need_rounds += 1;
            return Ok(vec![SyncMessage::Need { revisions: missing }]);
        }
        if self.sent_finished {
            return Ok(Vec::new());
        }
        self.report.pending = vault.staged_revision_ids()?.len();
        self.sent_finished = true;
        Ok(vec![SyncMessage::Finished])
    }
}
