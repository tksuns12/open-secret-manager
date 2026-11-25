//! The control-plane state machine. Applying a log entry depends only on the
//! entry and the state before it, so every node reaches the same state.
//!
//! Besides membership, the state carries the vault's key epochs: the current
//! epoch, a check committing every member to the same key for each epoch,
//! and each device's epoch keys sealed to its recipient key. A removal
//! carries the next epoch's key for every remaining member, and that epoch
//! becomes current only in the entry that completes the removal.
//!
//! A member is a voter or, if its enrollment said so, a learner without a
//! vote. Both are sent the log and given keys; only voters count toward the
//! majority every change needs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ed25519_dalek::VerifyingKey;
use openraft::{EntryPayload, LogId, StoredMembership};
use osm_vault_sync::{EpochKeyEnvelope, HpkePublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    ControlConfig, ControlEntry, ControlRequest, DeviceId, DeviceNode, MembershipChange, Outcome,
    Rejection, Rotation, SignedRequest,
};

/// How many applied request IDs are remembered for deduplication.
const REMEMBERED_REQUESTS: usize = 4096;
/// Bounds that keep a single request, and the state, reasonably sized.
const MAX_EPOCH: u64 = 1 << 32;
const MAX_EPOCHS: usize = 1024;
const MAX_AUTHORS: usize = 10_000;

/// A membership change accepted by the cluster and not yet completed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    pub request_id: [u8; 16],
    pub requester: DeviceId,
    pub change: MembershipChange,
    /// The voter set once the change has taken effect.
    pub target_voters: BTreeSet<DeviceId>,
    /// An enrollment that was cancelled: the change now leads back to the
    /// voters without the device.
    #[serde(default)]
    pub cancelled: bool,
    /// For a removal, the device's TLS pin when the removal was proposed.
    /// Its membership record is gone by the time the removal completes.
    #[serde(default)]
    pub removed_pin: Option<[u8; 32]>,
}

impl PendingChange {
    /// The device being enrolled or removed.
    pub fn subject(&self) -> DeviceId {
        match &self.change {
            MembershipChange::Enroll { device, .. } | MembershipChange::Remove { device, .. } => {
                *device
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlState {
    /// The vault this control plane belongs to; requests are signed for it.
    pub vault_id: [u8; 32],
    pub last_applied: Option<LogId<DeviceId>>,
    /// The last membership entry applied, i.e. the committed membership.
    pub membership: StoredMembership<DeviceId, DeviceNode>,
    pub pending: Option<PendingChange>,
    /// Recently accepted request IDs, oldest first. Only accepted requests
    /// are remembered: they are the ones with effects that must not repeat.
    /// A rejected request had no effect, so resubmitting it is evaluated
    /// again.
    pub applied_requests: VecDeque<([u8; 16], Outcome)>,
    /// The epoch new revisions are written under; 0 before genesis.
    pub epoch: u64,
    /// The key check of every epoch from 1 to `epoch`.
    pub epoch_checks: BTreeMap<u64, [u8; 32]>,
    /// Every device whose revisions the vault accepts or has accepted, with
    /// its signing key: the genesis authors and every enrolled device.
    pub authors: BTreeMap<DeviceId, [u8; 32]>,
    /// Removed devices, each with the device that removed it. Their stored
    /// revisions stay valid; they never rejoin.
    pub removed: BTreeMap<DeviceId, DeviceId>,
    /// The TLS pin each removed device had, so that it can be recognized
    /// and told it was removed when it next connects.
    #[serde(default)]
    pub removed_pins: BTreeMap<DeviceId, [u8; 32]>,
    /// The epochs whose keys each member has been given.
    pub keys_held: BTreeMap<DeviceId, BTreeSet<u64>>,
    /// Epoch keys sealed to each device, by epoch. The founding device
    /// holds its keys without envelopes.
    pub envelopes: BTreeMap<DeviceId, BTreeMap<u64, Vec<u8>>>,
    /// Devices enrolled without a vote: learners in the Raft membership.
    /// Absent from what is stored while there are none, as before they
    /// existed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub without_vote: BTreeSet<DeviceId>,
    /// The signed node record (signing key, TLS pin, HPKE recipient key) for
    /// each currently enrolled member, populated only from Genesis (founding
    /// voters) and completed signed Enroll requests. An unsigned Raft
    /// `EntryPayload::Membership` cannot alter these keys or pins.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enrolled_nodes: BTreeMap<DeviceId, DeviceNode>,
    /// In-memory fallback populated by `store::open` when opening an older
    /// database whose persisted `ControlState` predated `enrolled_nodes`.
    /// Omitted from serialization so frozen fixtures round-trip identically.
    #[serde(skip)]
    pub(crate) legacy_enrolled: BTreeMap<DeviceId, DeviceNode>,
    /// Enrollment request IDs that were explicitly cancelled, persisted
    /// permanently so FIFO eviction from `applied_requests` can never allow
    /// replaying an old cancelled `Enroll` proposal.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub cancelled_enrollments: BTreeSet<[u8; 16]>,
    /// In-memory fallback populated by `store::open` when opening a pre-existing
    /// database whose persisted `ControlState` predated `cancelled_enrollments`.
    #[serde(skip)]
    pub(crate) legacy_cancelled: BTreeSet<[u8; 16]>,
}

impl ControlState {
    pub fn new(vault_id: [u8; 32]) -> Self {
        Self {
            vault_id,
            ..Self::default()
        }
    }

    pub fn voters(&self) -> BTreeSet<DeviceId> {
        self.membership.voter_ids().collect()
    }

    /// The committed membership is a single configuration, not a joint one.
    pub fn is_uniform(&self) -> bool {
        self.membership.membership().get_joint_config().len() == 1
    }

    pub fn node(&self, device: DeviceId) -> Option<&DeviceNode> {
        self.membership.membership().get_node(&device)
    }

    /// The signed node record for an enrolled member (signing key, TLS pin,
    /// HPKE recipient key). Never altered by an unsigned Raft membership
    /// entry.
    pub fn enrolled_node(&self, device: DeviceId) -> Option<&DeviceNode> {
        self.enrolled_node_map().get(&device)
    }

    pub(crate) fn enrolled_node_map(&self) -> &BTreeMap<DeviceId, DeviceNode> {
        if !self.enrolled_nodes.is_empty() {
            &self.enrolled_nodes
        } else {
            &self.legacy_enrolled
        }
    }

    fn promote_legacy(&mut self) {
        if self.enrolled_nodes.is_empty() && !self.legacy_enrolled.is_empty() {
            self.enrolled_nodes = std::mem::take(&mut self.legacy_enrolled);
        }
        if !self.legacy_cancelled.is_empty() {
            self.cancelled_enrollments
                .extend(std::mem::take(&mut self.legacy_cancelled));
        }
    }

    pub(crate) fn is_cancelled_enrollment(&self, request_id: &[u8; 16]) -> bool {
        self.cancelled_enrollments.contains(request_id)
            || self.legacy_cancelled.contains(request_id)
    }

    /// Whether `device` is a member whose enrollment the vault's devices
    /// signed for, and whose removal they have not: a voter, or a device in
    /// the membership that was enrolled without a vote, recorded in
    /// `enrolled_nodes` with the signing key in `authors`, and not among the
    /// removed devices.
    ///
    /// Authority and epoch keys follow this, never voting rights or unsigned
    /// Raft membership records alone. A Raft membership entry carries no
    /// signature, so a device that held only a voter's transport identity
    /// could add voters, resurrect a removed device, or swap a member's
    /// `recipient_key`/`transport_pin`; without a standing signed enrollment
    /// they can neither make requests, substitute keys, nor be given keys.
    pub fn is_enrolled(&self, device: DeviceId) -> bool {
        let in_membership = if self.without_vote.contains(&device) {
            self.node(device).is_some()
        } else {
            self.voters().contains(&device)
        };
        in_membership
            && !self.removed.contains_key(&device)
            && self
                .enrolled_node(device)
                .is_some_and(|node| self.authors.get(&device) == Some(&node.public_key))
    }

    /// Whether `device` is an enrolled member that votes.
    pub fn votes(&self, device: DeviceId) -> bool {
        self.is_enrolled(device) && self.voters().contains(&device)
    }

    /// The enrolled members, voting or not; see [`Self::is_enrolled`].
    pub fn members(&self) -> BTreeSet<DeviceId> {
        self.membership
            .membership()
            .nodes()
            .map(|(device, _)| *device)
            .filter(|device| self.is_enrolled(*device))
            .collect()
    }

    pub fn outcome_of(&self, request_id: &[u8; 16]) -> Option<&Outcome> {
        self.applied_requests
            .iter()
            .find(|(id, _)| id == request_id)
            .map(|(_, outcome)| outcome)
    }

    /// Epochs up to the current one whose keys `device`, a voter or a
    /// member without a vote, has not been given yet. Empty for any other
    /// device.
    pub fn missing_epochs(&self, device: DeviceId) -> Vec<u64> {
        if !self.voters().contains(&device) && !self.without_vote.contains(&device) {
            return Vec::new();
        }
        let held = self.keys_held.get(&device);
        (1..=self.epoch)
            .filter(|epoch| !held.is_some_and(|held| held.contains(epoch)))
            .collect()
    }

    /// Whether `device` takes part in the vault: an enrolled member that has
    /// not been removed and whose removal is not pending. Unlike
    /// [`Self::is_settled_member`] this holds while another device's change
    /// is under way.
    pub fn is_active_member(&self, device: DeviceId) -> bool {
        self.is_enrolled(device)
            && !self.removed.contains_key(&device)
            && !self.pending.as_ref().is_some_and(|pending| {
                matches!(&pending.change, MembershipChange::Remove { device: leaving, .. } if *leaving == device)
            })
    }

    /// Whether `device` is an enrolled member that a pending change does not
    /// concern, so it is a full member.
    pub fn is_settled_member(&self, device: DeviceId) -> bool {
        self.is_uniform()
            && self.is_enrolled(device)
            && self
                .pending
                .as_ref()
                .is_none_or(|pending| pending.subject() != device)
    }

    pub(crate) fn apply(
        &mut self,
        log_id: LogId<DeviceId>,
        payload: &EntryPayload<ControlConfig>,
    ) -> Outcome {
        self.last_applied = Some(log_id);
        match payload {
            EntryPayload::Blank => Outcome::Recorded,
            EntryPayload::Membership(membership) => {
                self.membership = StoredMembership::new(Some(log_id), membership.clone());
                Outcome::Recorded
            }
            EntryPayload::Normal(ControlEntry::Request(request)) => {
                self.promote_legacy();
                self.apply_request(request)
            }
            EntryPayload::Normal(ControlEntry::Complete { request_id }) => {
                self.promote_legacy();
                self.complete(request_id)
            }
        }
    }

    fn apply_request(&mut self, signed: &SignedRequest) -> Outcome {
        if matches!(
            signed.request,
            ControlRequest::ProposeChange(MembershipChange::Enroll { .. })
        ) && self.is_cancelled_enrollment(&signed.request_id)
        {
            return Outcome::Rejected(Rejection::InvalidChange("enrollment was cancelled".into()));
        }
        if let Some(earlier) = self.outcome_of(&signed.request_id) {
            return Outcome::AlreadyApplied(Box::new(earlier.clone()));
        }
        let outcome = self.decide(signed);
        if outcome == Outcome::Accepted {
            if self.applied_requests.len() == REMEMBERED_REQUESTS {
                self.applied_requests.pop_front();
            }
            self.applied_requests
                .push_back((signed.request_id, outcome.clone()));
        }
        outcome
    }

    fn decide(&mut self, signed: &SignedRequest) -> Outcome {
        // Before the control plane is founded only a voter may ask, to found
        // it; afterwards only an enrolled member, voting or not: genesis and
        // every enrollment since were signed, so authority traces back to
        // the founder rather than to whatever the Raft membership contains.
        // Either way with its own signed key rather than an unsigned
        // membership record.
        let may_ask = if self.epoch == 0 {
            self.voters().contains(&signed.requester)
        } else {
            self.is_enrolled(signed.requester)
        };
        if !may_ask {
            return Outcome::Rejected(Rejection::Unauthorized);
        }
        let requester_key = if self.epoch == 0 {
            self.node(signed.requester).map(|node| node.public_key)
        } else {
            self.enrolled_node(signed.requester)
                .map(|node| node.public_key)
        };
        let Some(requester_key) = requester_key else {
            return Outcome::Rejected(Rejection::Unauthorized);
        };
        if !signed.verify(&self.vault_id, &requester_key) {
            return Outcome::Rejected(Rejection::BadSignature);
        }
        let result = match &signed.request {
            ControlRequest::Genesis {
                epoch,
                checks,
                authors,
            } => self.genesis(signed.requester, *epoch, checks, authors),
            _ if self.epoch == 0 => Err(Rejection::NotInitialized),
            ControlRequest::ProposeChange(change) => self.propose(signed, change),
            ControlRequest::CancelEnrollment { request_id } => self.cancel(request_id),
            ControlRequest::GrantKeys { device, envelopes } => self.grant(*device, envelopes),
        };
        match result {
            Ok(()) => Outcome::Accepted,
            Err(rejection) => Outcome::Rejected(rejection),
        }
    }

    fn genesis(
        &mut self,
        founder: DeviceId,
        epoch: u64,
        checks: &[[u8; 32]],
        authors: &[(DeviceId, [u8; 32])],
    ) -> Result<(), Rejection> {
        if self.epoch != 0 {
            return Err(invalid("the control plane is already founded"));
        }
        if epoch == 0 || epoch as usize > MAX_EPOCHS || checks.len() as u64 != epoch {
            return Err(invalid("genesis needs a check for every epoch"));
        }
        if authors.len() > MAX_AUTHORS {
            return Err(invalid("too many authors"));
        }
        let mut author_keys = BTreeMap::new();
        for (device, public_key) in authors {
            if VerifyingKey::from_bytes(public_key).is_err()
                || author_keys.insert(*device, *public_key).is_some()
            {
                return Err(invalid("invalid author list"));
            }
        }
        // Every founding voter is an author and an enrolled node, with the
        // node record membership held at genesis. Non-voter historical authors
        // stay in `authors` (so old revisions remain verifiable) and are NOT
        // added to `enrolled_nodes`.
        let mut enrolled = BTreeMap::new();
        for voter in self.voters() {
            let Some(node) = self.node(voter) else {
                return Err(invalid("a voter has no node record"));
            };
            match author_keys.get(&voter) {
                Some(listed) if *listed != node.public_key => {
                    return Err(invalid("an author's key differs from its voter key"))
                }
                Some(_) => {}
                None => {
                    author_keys.insert(voter, node.public_key);
                }
            }
            enrolled.insert(voter, node.clone());
        }
        self.epoch = epoch;
        self.epoch_checks = (1..=epoch).zip(checks.iter().copied()).collect();
        self.authors = author_keys;
        self.enrolled_nodes = enrolled;
        self.keys_held.insert(founder, (1..=epoch).collect());
        Ok(())
    }

    fn propose(
        &mut self,
        signed: &SignedRequest,
        change: &MembershipChange,
    ) -> Result<(), Rejection> {
        if self.pending.is_some() {
            return Err(Rejection::ChangeInProgress);
        }
        let mut target = self.voters();
        match change {
            MembershipChange::Enroll {
                device,
                node,
                votes,
            } => {
                if self.removed.contains_key(device) {
                    return Err(invalid("a removed device cannot rejoin"));
                }
                if target.contains(device) || self.is_enrolled(*device) {
                    return Err(invalid("device is already a member"));
                }
                if *votes {
                    target.insert(*device);
                }
                if self
                    .authors
                    .get(device)
                    .is_some_and(|key| *key != node.public_key)
                {
                    return Err(invalid("device is an author with a different key"));
                }
                if VerifyingKey::from_bytes(&node.public_key).is_err()
                    || HpkePublicKey::from_bytes(node.recipient_key).is_err()
                {
                    return Err(invalid("invalid device keys"));
                }
                // A transport certificate identifies one device: peers map
                // a connection's certificate back to a device ID.
                if self.enrolled_node_map().iter().any(|(known, recorded)| {
                    known != device && recorded.transport_pin == node.transport_pin
                }) || self
                    .membership
                    .membership()
                    .nodes()
                    .any(|(known, recorded)| {
                        known != device && recorded.transport_pin == node.transport_pin
                    })
                {
                    return Err(invalid(
                        "the transport certificate belongs to another device",
                    ));
                }
            }
            MembershipChange::Remove { device, rotation } => {
                if *device == signed.requester {
                    return Err(invalid("a device cannot remove itself"));
                }
                if !target.remove(device) && !self.is_enrolled(*device) {
                    return Err(invalid("device is not a member"));
                }
                // Raft makes no change to a membership without a voter, so
                // such a removal would never complete and would block every
                // change after it. Only a member without a vote can ask for
                // it, as a device cannot remove itself.
                if target.is_empty() {
                    return Err(invalid("the only device that votes cannot be removed"));
                }
                // The new key goes to the enrolled members that remain,
                // voting or not.
                let remaining = target
                    .iter()
                    .copied()
                    .chain(self.without_vote.iter().copied())
                    .filter(|member| member != device && self.is_enrolled(*member))
                    .collect();
                self.check_rotation(rotation, &remaining)?;
            }
        }
        let removed_pin = match change {
            MembershipChange::Remove { device, .. } => self
                .enrolled_node(*device)
                .or_else(|| self.node(*device))
                .map(|node| node.transport_pin),
            MembershipChange::Enroll { .. } => None,
        };
        self.pending = Some(PendingChange {
            request_id: signed.request_id,
            requester: signed.requester,
            change: change.clone(),
            target_voters: target,
            cancelled: false,
            removed_pin,
        });
        Ok(())
    }

    /// The rotation introduces the next epoch with exactly one valid
    /// envelope for each remaining member.
    fn check_rotation(
        &self,
        rotation: &Rotation,
        remaining: &BTreeSet<DeviceId>,
    ) -> Result<(), Rejection> {
        if rotation.epoch != self.epoch + 1 || rotation.epoch > MAX_EPOCH {
            return Err(invalid("a removal must introduce the next epoch"));
        }
        let recipients: BTreeSet<DeviceId> = rotation
            .envelopes
            .iter()
            .map(|(device, _)| *device)
            .collect();
        if recipients.len() != rotation.envelopes.len() || &recipients != remaining {
            return Err(invalid(
                "the new key must be sealed to each remaining member",
            ));
        }
        for (device, envelope) in &rotation.envelopes {
            self.check_envelope(*device, rotation.epoch, envelope)?;
        }
        Ok(())
    }

    /// The envelope is for this vault and `epoch`, and is sealed to
    /// `device`'s signed enrollment keys (never an unsigned membership entry).
    fn check_envelope(
        &self,
        device: DeviceId,
        epoch: u64,
        envelope: &[u8],
    ) -> Result<(), Rejection> {
        let node = self
            .enrolled_node(device)
            .ok_or_else(|| invalid("envelope for an unknown device"))?;
        let envelope =
            EpochKeyEnvelope::from_bytes(envelope).map_err(|_| invalid("malformed envelope"))?;
        if envelope.vault_id().0 != self.vault_id
            || envelope.epoch() != epoch
            || envelope.recipient().0 != node.public_key
            || envelope.recipient_key().as_bytes() != node.recipient_key
        {
            return Err(invalid("envelope is not sealed to that device and epoch"));
        }
        Ok(())
    }

    fn cancel(&mut self, request_id: &[u8; 16]) -> Result<(), Rejection> {
        let Some(pending) = self.pending.as_mut() else {
            return Err(Rejection::NotPending);
        };
        let MembershipChange::Enroll { device, .. } = &pending.change else {
            return Err(Rejection::NotPending);
        };
        if pending.request_id != *request_id || pending.cancelled {
            return Err(Rejection::NotPending);
        }
        // The device never received keys: grants wait until its enrollment
        // completes. The leader now steers back to the membership without
        // it, and the request ID is permanently remembered as cancelled so
        // FIFO eviction from `applied_requests` cannot re-enable replay.
        pending.target_voters.remove(device);
        pending.cancelled = true;
        self.cancelled_enrollments.insert(*request_id);
        Ok(())
    }

    fn grant(&mut self, device: DeviceId, envelopes: &[Vec<u8>]) -> Result<(), Rejection> {
        if !self.is_settled_member(device) {
            return Err(invalid(
                "keys go only to a member whose enrollment is complete",
            ));
        }
        if envelopes.is_empty() || envelopes.len() > MAX_EPOCHS {
            return Err(invalid("invalid number of envelopes"));
        }
        let missing: BTreeSet<u64> = self.missing_epochs(device).into_iter().collect();
        let mut granted = BTreeMap::new();
        for envelope in envelopes {
            let epoch = EpochKeyEnvelope::from_bytes(envelope)
                .map_err(|_| invalid("malformed envelope"))?
                .epoch();
            if !missing.contains(&epoch) || granted.contains_key(&epoch) {
                return Err(invalid("the device already holds that epoch's key"));
            }
            self.check_envelope(device, epoch, envelope)?;
            granted.insert(epoch, envelope.clone());
        }
        for (epoch, envelope) in granted {
            self.record_key(device, epoch, envelope);
        }
        Ok(())
    }

    fn record_key(&mut self, device: DeviceId, epoch: u64, envelope: Vec<u8>) {
        self.keys_held.entry(device).or_default().insert(epoch);
        self.envelopes
            .entry(device)
            .or_default()
            .insert(epoch, envelope);
    }

    /// Applies the leader's record that the pending change took effect.
    /// Not deduplicated by ID: once accepted, the change is no longer
    /// pending, so a repeat is simply `NotPending`.
    fn complete(&mut self, request_id: &[u8; 16]) -> Outcome {
        let effective = self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request_id == *request_id && self.in_effect(pending));
        if !effective {
            return Outcome::Rejected(Rejection::NotPending);
        }
        let Some(pending) = self.pending.take() else {
            return Outcome::Rejected(Rejection::NotPending);
        };
        match pending.change {
            MembershipChange::Enroll {
                device,
                node,
                votes,
            } => {
                if !pending.cancelled {
                    self.authors.insert(device, node.public_key);
                    self.enrolled_nodes.insert(device, node);
                    if !votes {
                        self.without_vote.insert(device);
                    }
                }
            }
            MembershipChange::Remove { device, rotation } => {
                self.without_vote.remove(&device);
                self.enrolled_nodes.remove(&device);
                self.epoch = rotation.epoch;
                self.epoch_checks.insert(rotation.epoch, rotation.check);
                for (recipient, envelope) in rotation.envelopes {
                    self.record_key(recipient, rotation.epoch, envelope);
                }
                self.keys_held.remove(&device);
                self.envelopes.remove(&device);
                // A device can be removed again if a membership entry, which
                // carries no signature, made it a voter again; the record of
                // its first removal stands.
                self.removed.entry(device).or_insert(pending.requester);
                if let Some(pin) = pending.removed_pin {
                    self.removed_pins.entry(device).or_insert(pin);
                }
            }
        }
        Outcome::Accepted
    }
}

impl ControlState {
    /// Whether the committed membership is what the pending change leads
    /// to: uniform, with its target voters, with the signed `DeviceNode`
    /// recorded for a joining device, and, for a member without a vote, with
    /// that device present when it joins and gone when it is removed.
    pub fn in_effect(&self, pending: &PendingChange) -> bool {
        if !(self.is_uniform() && self.voters() == pending.target_voters) {
            return false;
        }
        match &pending.change {
            MembershipChange::Enroll { device, node, .. } if !pending.cancelled => {
                self.node(*device) == Some(node)
            }
            MembershipChange::Remove { device, .. } if self.without_vote.contains(device) => {
                self.node(*device).is_none()
            }
            _ => true,
        }
    }
}

fn invalid(reason: &str) -> Rejection {
    Rejection::InvalidChange(reason.into())
}
