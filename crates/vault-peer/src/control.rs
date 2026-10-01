//! Couples a vault to its membership control plane.
//!
//! Committed control state decides which devices may write, which key
//! epoch is current, and which epoch keys each device has been given;
//! [`reconcile`] brings a vault in line with it. The request builders
//! produce what an unlocked member signs and submits: founding the control
//! plane, enrolling a paired device, removing a device with a new epoch key,
//! cancelling a stalled enrollment, and giving a new voter the existing keys.
//!
//! Request IDs are derived from what a request is about, so retrying after
//! an unknown outcome (`QuorumUnavailable`) is recognized as the same
//! request rather than a second rotation or grant.

use std::collections::{BTreeMap, BTreeSet};

use osm_vault_core::{epoch_key_check, Vault};
use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlNode, ControlRequest, ControlState, DeviceId,
    DeviceNode, MembershipChange, Outcome, Rotation, SignedRequest,
};
use osm_vault_sync::{
    open_epoch_key, seal_epoch_key, EpochKeyEnvelope, HpkeKeyPair, HpkePublicKey, VaultId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, PeerStore, Result};

/// This device as committed membership records it: its revision key, TLS
/// pin, and HPKE recipient key. Needs the vault unlocked.
pub fn local_node(vault: &Vault, peers: &mut PeerStore) -> Result<(DeviceId, DeviceNode)> {
    let (device, public_key) = own_identity(vault)?;
    let recipient = HpkeKeyPair::from_secret(&*vault.recipient_secret()?);
    Ok((
        device,
        DeviceNode {
            public_key,
            transport_pin: peers.transport_identity()?.pin(),
            recipient_key: recipient.public().as_bytes(),
        },
    ))
}

/// Everything needed to found a vault's control plane, taken from the
/// unlocked vault. Committing it does not need the vault.
pub struct Founding {
    device: DeviceId,
    node: DeviceNode,
    genesis: SignedRequest,
}

impl Founding {
    pub fn prepare(vault: &Vault, peers: &mut PeerStore) -> Result<Self> {
        let (device, node) = local_node(vault, peers)?;
        Ok(Self {
            device,
            node,
            genesis: genesis_request(vault)?,
        })
    }

    /// Forms a cluster with this device as its only voter and commits
    /// genesis. Doing it again after an interruption finishes what is
    /// missing.
    pub async fn commit(self, node: &ControlNode) -> Result<()> {
        let initialized = node
            .raft()
            .is_initialized()
            .await
            .map_err(osm_vault_membership::Error::from)?;
        if !initialized {
            node.initialize(BTreeMap::from([(self.device, self.node)]))
                .await?;
        }
        submit(node, self.genesis).await
    }
}

/// Founds the vault's control plane on this device: a cluster with this
/// device as its only voter, and genesis recording the vault's epochs and
/// authors. Every later member joins through enrollment. Calling it again
/// after an interruption finishes what is missing.
pub async fn found(vault: &Vault, peers: &mut PeerStore, node: &ControlNode) -> Result<()> {
    Founding::prepare(vault, peers)?.commit(node).await
}

/// The genesis request: the vault's current epoch, the check of every epoch
/// key this device holds (which must be every epoch so far), and the
/// authorized authors.
pub fn genesis_request(vault: &Vault) -> Result<SignedRequest> {
    let vault_id = vault.vault_id();
    let keys = vault.epoch_keys()?;
    let epoch = vault.current_epoch();
    let checks = (1..=epoch)
        .map(|wanted| {
            keys.iter()
                .find(|(epoch, _)| *epoch == wanted)
                .map(|(epoch, key)| epoch_key_check(&vault_id, *epoch, key))
                .ok_or(osm_vault_core::Error::MissingEpochKey)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let authors = vault
        .authorized_devices()?
        .into_iter()
        .map(|(device, key)| (device_id_from_bytes(device), key))
        .collect();
    sign(
        vault,
        request_id(&vault_id, b"genesis", &[]),
        ControlRequest::Genesis {
            epoch,
            checks,
            authors,
        },
    )
}

/// Proposes enrolling a device. Only for a device the owner confirmed by
/// pairing; see `approve_enrollment`.
pub fn enrollment_request(
    vault: &Vault,
    device: [u8; 16],
    node: DeviceNode,
) -> Result<SignedRequest> {
    let vault_id = vault.vault_id();
    sign(
        vault,
        request_id(&vault_id, b"enroll", &device),
        ControlRequest::ProposeChange(MembershipChange::Enroll {
            device: device_id_from_bytes(device),
            node,
        }),
    )
}

/// Proposes removing `device`, with a new epoch key sealed to every other
/// enrolled member in `state`. The key is not kept here: this device, like every
/// remaining one, recovers it from its own envelope once the removal
/// completes, so nothing can activate it early.
pub fn removal_request(
    vault: &Vault,
    state: &ControlState,
    device: [u8; 16],
) -> Result<SignedRequest> {
    let vault_id = vault.vault_id();
    let removed = device_id_from_bytes(device);
    let epoch = state.epoch + 1;
    let key = random_key()?;
    let envelopes = state
        .members()
        .into_iter()
        .filter(|member| *member != removed)
        .map(|member| Ok((member, seal(state, member, epoch, &key)?)))
        .collect::<Result<Vec<_>>>()?;
    sign(
        vault,
        request_id(
            &vault_id,
            b"remove",
            &[&device[..], &epoch.to_be_bytes()].concat(),
        ),
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: removed,
            rotation: Rotation {
                epoch,
                check: epoch_key_check(&vault_id, epoch, &key),
                envelopes,
            },
        }),
    )
}

/// Abandons the pending enrollment `request_id`, for a device that never
/// came online. It never received keys.
pub fn cancel_request(vault: &Vault, request_id: [u8; 16]) -> Result<SignedRequest> {
    let vault_id = vault.vault_id();
    sign(
        vault,
        self::request_id(&vault_id, b"cancel", &request_id),
        ControlRequest::CancelEnrollment { request_id },
    )
}

/// Grants every enrolled voter the epoch keys it lacks and this device
/// holds. Any unlocked member may send these; the first to commit wins and
/// a repeat is recognized.
pub fn grant_requests(vault: &Vault, state: &ControlState) -> Result<Vec<SignedRequest>> {
    let vault_id = vault.vault_id();
    let keys: BTreeMap<u64, _> = vault.epoch_keys()?.into_iter().collect();
    let mut requests = Vec::new();
    for voter in state.voters() {
        if !state.is_settled_member(voter) {
            continue;
        }
        let epochs: Vec<u64> = state
            .missing_epochs(voter)
            .into_iter()
            .filter(|epoch| keys.contains_key(epoch))
            .collect();
        if epochs.is_empty() {
            continue;
        }
        let envelopes = epochs
            .iter()
            .map(|epoch| seal(state, voter, *epoch, &keys[epoch]))
            .collect::<Result<Vec<_>>>()?;
        let subject: Vec<u8> = device_id_to_bytes(voter)
            .into_iter()
            .chain(epochs.iter().flat_map(|epoch| epoch.to_be_bytes()))
            .collect();
        requests.push(sign(
            vault,
            request_id(&vault_id, b"grant", &subject),
            ControlRequest::GrantKeys {
                device: voter,
                envelopes,
            },
        )?);
    }
    Ok(requests)
}

/// Submits a request and requires that it is (or already was) accepted.
pub async fn submit(node: &ControlNode, request: SignedRequest) -> Result<()> {
    match node.submit(request).await? {
        outcome if outcome.is_accepted() => Ok(()),
        Outcome::Rejected(rejection) => Err(Error::Rejected(rejection)),
        Outcome::AlreadyApplied(earlier) => match *earlier {
            Outcome::Rejected(rejection) => Err(Error::Rejected(rejection)),
            _ => Err(Error::ProtocolViolation),
        },
        Outcome::Accepted | Outcome::Recorded => Err(Error::ProtocolViolation),
    }
}

/// What [`reconcile`] changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Authors newly authorized.
    pub authorized: usize,
    /// Devices newly revoked.
    pub revoked: usize,
    /// Epoch keys installed from envelopes.
    pub installed: Vec<u64>,
    /// The epoch new writes moved to.
    pub activated: Option<u64>,
    /// Held revisions applied because their author is now authorized.
    pub released: usize,
    /// A removed device's heads endorsed by this device, which removed it.
    pub endorsed: usize,
    /// Epochs whose keys this device has not been given yet. While the
    /// current one is among them, writes stay fenced.
    pub awaiting_keys: Vec<u64>,
    /// Committed membership removed this device.
    pub removed: bool,
}

/// Brings the vault in line with committed control state.
///
/// While locked it only raises the write fence to the committed epoch, so
/// nothing is written under a superseded key. Unlocked, it also authorizes
/// every author, revokes removed devices, installs the epoch keys sealed to
/// this device (each checked against its committed check), activates the
/// current epoch, applies held revisions whose authors are now authorized,
/// and endorses the last heads of devices this device removed. Call it
/// whenever the state changes and right after unlocking, before processing
/// staged revisions or writing. It is idempotent.
pub fn reconcile(vault: &mut Vault, state: &ControlState) -> Result<Reconciled> {
    let mut report = Reconciled::default();
    if state.epoch == 0 {
        return Ok(report);
    }
    if state.vault_id != vault.vault_id() {
        return Err(Error::VaultMismatch);
    }
    let own = vault.device_id().ok_or(osm_vault_core::Error::Locked)?;
    let me = device_id_from_bytes(own);
    if state.removed.contains_key(&me) {
        report.removed = true;
        return Ok(report);
    }
    if state.epoch > vault.current_epoch() {
        vault.raise_write_fence(state.epoch)?;
    }
    if !vault.is_unlocked() {
        return Ok(report);
    }

    let authorized: BTreeMap<[u8; 16], [u8; 32]> =
        vault.authorized_devices()?.into_iter().collect();
    for (device, key) in &state.authors {
        let device = device_id_to_bytes(*device);
        match authorized.get(&device) {
            Some(known) if known == key => {}
            Some(_) => return Err(Error::ProtocolViolation),
            None => {
                vault.authorize_device(device, *key)?;
                report.authorized += 1;
            }
        }
    }
    let revoked: BTreeSet<[u8; 16]> = vault.revoked_devices()?.into_iter().collect();
    for device in state.removed.keys() {
        let device = device_id_to_bytes(*device);
        if !revoked.contains(&device) && vault.revoke_device(device)? {
            report.revoked += 1;
        }
    }

    let vault_id = vault.vault_id();
    let recipient = HpkeKeyPair::from_secret(&*vault.recipient_secret()?);
    let held: BTreeMap<u64, _> = vault.epoch_keys()?.into_iter().collect();
    let sealed = state.envelopes.get(&me);
    for (epoch, check) in &state.epoch_checks {
        if let Some(key) = held.get(epoch) {
            if epoch_key_check(&vault_id, *epoch, key) != *check {
                return Err(Error::EpochKeyMismatch);
            }
            continue;
        }
        let Some(envelope) = sealed.and_then(|sealed| sealed.get(epoch)) else {
            report.awaiting_keys.push(*epoch);
            continue;
        };
        let key = open(&vault_id, *epoch, own_key(vault)?, &recipient, envelope)?;
        if epoch_key_check(&vault_id, *epoch, &key) != *check {
            return Err(Error::EpochKeyMismatch);
        }
        vault.install_epoch_key(*epoch, &key)?;
        report.installed.push(*epoch);
    }
    if state.epoch > vault.current_epoch() && !report.awaiting_keys.contains(&state.epoch) {
        vault.activate_epoch(state.epoch)?;
        report.activated = Some(state.epoch);
    }

    report.released = vault.retry_quarantined()?;
    // Endorsing writes under the current epoch, so only once it is active.
    if vault.current_epoch() >= vault.write_fence() {
        for (device, remover) in &state.removed {
            if *remover == me {
                report.endorsed += vault.endorse_heads_of(device_id_to_bytes(*device))?.len();
            }
        }
    }
    Ok(report)
}

/// Seals `key` for `epoch` to `device`'s keys as membership records them.
fn seal(state: &ControlState, device: DeviceId, epoch: u64, key: &[u8; 32]) -> Result<Vec<u8>> {
    let node = state.node(device).ok_or(Error::ProtocolViolation)?;
    Ok(seal_epoch_key(
        VaultId(state.vault_id),
        epoch,
        osm_vault_sync::DeviceId(node.public_key),
        HpkePublicKey::from_bytes(node.recipient_key)?,
        key,
    )?
    .to_bytes()
    .to_vec())
}

/// Opens an envelope sealed to this device for `epoch`.
pub(crate) fn open(
    vault_id: &[u8; 32],
    epoch: u64,
    public_key: [u8; 32],
    recipient: &HpkeKeyPair,
    envelope: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let envelope = EpochKeyEnvelope::from_bytes(envelope)?;
    Ok(open_epoch_key(
        &envelope,
        VaultId(*vault_id),
        epoch,
        osm_vault_sync::DeviceId(public_key),
        recipient.private(),
    )?)
}

fn own_identity(vault: &Vault) -> Result<(DeviceId, [u8; 32])> {
    let device = vault.device_id().ok_or(osm_vault_core::Error::Locked)?;
    Ok((device_id_from_bytes(device), own_key(vault)?))
}

fn own_key(vault: &Vault) -> Result<[u8; 32]> {
    Ok(vault
        .device_public_key()
        .ok_or(osm_vault_core::Error::Locked)?)
}

fn sign(vault: &Vault, request_id: [u8; 16], request: ControlRequest) -> Result<SignedRequest> {
    let (requester, _) = own_identity(vault)?;
    Ok(SignedRequest::sign_with(
        &vault.vault_id(),
        request_id,
        requester,
        request,
        |message| vault.sign_control(message),
    )?)
}

/// A stable request ID for `kind` of request about `subject`.
fn request_id(vault_id: &[u8; 32], kind: &[u8], subject: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"osm-control-request-id-v1\0")
        .chain_update(vault_id)
        .chain_update((kind.len() as u64).to_be_bytes())
        .chain_update(kind)
        .chain_update(subject)
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn random_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| osm_vault_sync::Error::Randomness)?;
    Ok(key)
}
