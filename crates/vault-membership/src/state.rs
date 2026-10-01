//! The control-plane state machine. Applying a log entry depends only on the
//! entry and the state before it, so every node reaches the same state.

use std::collections::{BTreeSet, VecDeque};

use openraft::{EntryPayload, LogId, StoredMembership};
use serde::{Deserialize, Serialize};

use crate::{
    ControlConfig, ControlRequest, DeviceId, DeviceNode, MembershipChange, Outcome, Rejection,
    SignedRequest,
};

/// How many applied request IDs are remembered for deduplication.
const REMEMBERED_REQUESTS: usize = 4096;

/// A membership change accepted by the cluster and not yet completed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    pub request_id: [u8; 16],
    pub requester: DeviceId,
    pub change: MembershipChange,
    /// The voter set once the change has taken effect.
    pub target_voters: BTreeSet<DeviceId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlState {
    pub last_applied: Option<LogId<DeviceId>>,
    /// The last membership entry applied, i.e. the committed membership.
    pub membership: StoredMembership<DeviceId, DeviceNode>,
    pub pending: Option<PendingChange>,
    /// Recently accepted request IDs, oldest first. Only accepted requests
    /// are remembered: they are the ones with effects that must not repeat.
    /// A rejected request had no effect, so resubmitting it is evaluated
    /// again; a leader's derived completion ID can never be stuck behind a
    /// completion that arrived too early.
    pub applied_requests: VecDeque<([u8; 16], Outcome)>,
}

impl ControlState {
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

    pub fn outcome_of(&self, request_id: &[u8; 16]) -> Option<&Outcome> {
        self.applied_requests
            .iter()
            .find(|(id, _)| id == request_id)
            .map(|(_, outcome)| outcome)
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
            EntryPayload::Normal(request) => self.apply_request(request),
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
        // key as recorded in the committed membership.
        if !self.voters().contains(&signed.requester) {
            return Outcome::Rejected(Rejection::Unauthorized);
        }
        let Some(requester) = self.node(signed.requester) else {
            return Outcome::Rejected(Rejection::Unauthorized);
        };
        if !signed.verify(&requester.public_key) {
            return Outcome::Rejected(Rejection::BadSignature);
        }
        match &signed.request {
            ControlRequest::ProposeChange(change) => {
                if self.pending.is_some() {
                    return Outcome::Rejected(Rejection::ChangeInProgress);
                }
                let mut target = self.voters();
                match change {
                    MembershipChange::Enroll { device, .. } => {
                        if !target.insert(*device) {
                            return Outcome::Rejected(Rejection::InvalidChange(
                                "device is already a voter".into(),
                            ));
                        }
                    }
                    MembershipChange::Remove { device } => {
                        if !target.remove(device) {
                            return Outcome::Rejected(Rejection::InvalidChange(
                                "device is not a voter".into(),
                            ));
                        }
                        if target.is_empty() {
                            return Outcome::Rejected(Rejection::InvalidChange(
                                "the last voter cannot be removed".into(),
                            ));
                        }
                    }
                }
                self.pending = Some(PendingChange {
                    request_id: signed.request_id,
                    requester: signed.requester,
                    change: change.clone(),
                    target_voters: target,
                });
                Outcome::Accepted
            }
            ControlRequest::CompleteChange { request_id } => {
                let effective = self.pending.as_ref().is_some_and(|pending| {
                    pending.request_id == *request_id
                        && self.is_uniform()
                        && self.voters() == pending.target_voters
                });
                if !effective {
                    return Outcome::Rejected(Rejection::NotPending);
                }
                self.pending = None;
                Outcome::Accepted
            }
        }
    }
}
