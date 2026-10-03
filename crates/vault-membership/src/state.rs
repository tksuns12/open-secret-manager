//! The control-plane state machine. Applying a log entry depends only on the
//! entry and the state before it, so every node reaches the same state.
//!
//! Besides membership, the state carries the vault's key epochs: the current
//! epoch, a check committing every member to the same key for each epoch,
//! and each device's epoch keys sealed to its recipient key. A removal
//! carries the next epoch's key for every remaining voter, and that epoch
//! becomes current only in the entry that completes the removal.

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
    /// The epochs whose keys each voter has been given.
    pub keys_held: BTreeMap<DeviceId, BTreeSet<u64>>,
    /// Epoch keys sealed to each device, by epoch. The founding device
    /// holds its keys without envelopes.
    pub envelopes: BTreeMap<DeviceId, BTreeMap<u64, Vec<u8>>>,
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

    /// Whether `device` is a voter whose enrollment the vault's devices
    /// signed for, and whose removal they have not: an author under the key
    /// membership records for it, not among the removed devices.
    ///
    /// Authority and epoch keys follow this, never voting rights alone. A
    /// Raft membership entry carries no signature, so a device that held
    /// only a voter's transport identity could add voters, a removed device
    /// among them; without a standing signed enrollment they can neither
    /// make requests nor be given keys.
    pub fn is_enrolled(&self, device: DeviceId) -> bool {
        self.voters().contains(&device)
            && !self.removed.contains_key(&device)
            && self
                .node(device)
                .is_some_and(|node| self.authors.get(&device) == Some(&node.public_key))
    }

    /// The enrolled voters; see [`Self::is_enrolled`].
    pub fn members(&self) -> BTreeSet<DeviceId> {
        self.voters()
            .into_iter()
            .filter(|device| self.is_enrolled(*device))
            .collect()
    }

    pub fn outcome_of(&self, request_id: &[u8; 16]) -> Option<&Outcome> {
        self.applied_requests
            .iter()
            .find(|(id, _)| id == request_id)
            .map(|(_, outcome)| outcome)
    }

    /// Epochs up to the current one whose keys `device`, a voter, has not
    /// been given yet. Empty for a device that is not a voter.
    pub fn missing_epochs(&self, device: DeviceId) -> Vec<u64> {
        if !self.voters().contains(&device) {
            return Vec::new();
        }
        let held = self.keys_held.get(&device);
        (1..=self.epoch)
            .filter(|epoch| !held.is_some_and(|held| held.contains(epoch)))
            .collect()
    }

    /// Whether `device` takes part in the vault: an enrolled voter that has
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

    /// Whether `device` is an enrolled voter that a pending change does not
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
            EntryPayload::Normal(ControlEntry::Request(request)) => self.apply_request(request),
            EntryPayload::Normal(ControlEntry::Complete { request_id }) => {
                self.complete(request_id)
            }
        }
    }

    fn apply_request(&mut self, signed: &SignedRequest) -> Outcome {
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
        // Only a current voter may ask for anything, and only with its own
        // key as recorded in the committed membership. Once the control
        // plane is founded it must also be enrolled: genesis and every
        // enrollment since were signed, so authority traces back to the
        // founder rather than to whatever the Raft membership contains.
        if !self.voters().contains(&signed.requester) {
            return Outcome::Rejected(Rejection::Unauthorized);
        }
        let Some(requester) = self.node(signed.requester) else {
            return Outcome::Rejected(Rejection::Unauthorized);
        };
        if self.epoch != 0 && !self.is_enrolled(signed.requester) {
            return Outcome::Rejected(Rejection::Unauthorized);
        }
        if !signed.verify(&self.vault_id, &requester.public_key) {
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
        // Every voter is an author, with the key membership records.
        for voter in self.voters() {
            let key = self.node(voter).map(|node| node.public_key);
            match author_keys.get(&voter) {
                Some(listed) if Some(*listed) != key => {
                    return Err(invalid("an author's key differs from its voter key"))
                }
                Some(_) => {}
                None => {
                    author_keys.insert(voter, key.unwrap_or_default());
                }
            }
        }
        self.epoch = epoch;
        self.epoch_checks = (1..=epoch).zip(checks.iter().copied()).collect();
        self.authors = author_keys;
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
            MembershipChange::Enroll { device, node } => {
                if self.removed.contains_key(device) {
                    return Err(invalid("a removed device cannot rejoin"));
                }
                if !target.insert(*device) {
                    return Err(invalid("device is already a voter"));
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
                if self
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
                if !target.remove(device) {
                    return Err(invalid("device is not a voter"));
                }
                // The new key goes to the enrolled devices that remain.
                let remaining = target
                    .iter()
                    .copied()
                    .filter(|voter| self.is_enrolled(*voter))
                    .collect();
                self.check_rotation(rotation, &remaining)?;
            }
        }
        let removed_pin = match change {
            MembershipChange::Remove { device, .. } => {
                self.node(*device).map(|node| node.transport_pin)
            }
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
    /// `device`'s keys as membership records them.
    fn check_envelope(
        &self,
        device: DeviceId,
        epoch: u64,
        envelope: &[u8],
    ) -> Result<(), Rejection> {
        let node = self
            .node(device)
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
        // completes. The leader now steers back to the voters without it.
        pending.target_voters.remove(device);
        pending.cancelled = true;
        Ok(())
    }

    fn grant(&mut self, device: DeviceId, envelopes: &[Vec<u8>]) -> Result<(), Rejection> {
        if !self.is_settled_member(device) {
            return Err(invalid(
                "keys go only to a voter whose enrollment is complete",
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
        let effective = self.pending.as_ref().is_some_and(|pending| {
            pending.request_id == *request_id
                && self.is_uniform()
                && self.voters() == pending.target_voters
        });
        if !effective {
            return Outcome::Rejected(Rejection::NotPending);
        }
        let Some(pending) = self.pending.take() else {
            return Outcome::Rejected(Rejection::NotPending);
        };
        match pending.change {
            MembershipChange::Enroll { device, node } => {
                if !pending.cancelled {
                    self.authors.insert(device, node.public_key);
                }
            }
            MembershipChange::Remove { device, rotation } => {
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

fn invalid(reason: &str) -> Rejection {
    Rejection::InvalidChange(reason.into())
}
