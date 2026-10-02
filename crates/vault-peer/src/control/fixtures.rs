//! The frozen request IDs: a retry of a request has to be recognized as the
//! same request by every build.

use serde_json::json;

use super::*;
use crate::fixture::{counting, frozen, hex};

#[test]
fn request_ids_are_the_frozen_ones() {
    let vault_id: [u8; 32] = counting(0x10);
    let device: [u8; 16] = counting(0x40);
    let epoch = 3_u64;
    let pending: [u8; 16] = counting(0xe0);
    let grant: Vec<u8> = device
        .into_iter()
        .chain([1_u64, 2].iter().flat_map(|epoch| epoch.to_be_bytes()))
        .collect();
    let made = json!({
        "about": "The ID of each kind of control request: the first 16 bytes of SHA-256 over osm-control-request-id-v1, a zero byte, the vault ID, the kind's length as 8 big-endian bytes, the kind, and the subject.",
        "inputs": {
            "vault_id": hex(&vault_id),
            "device": hex(&device),
            "epoch": epoch,
            "pending_enrollment": hex(&pending),
            "granted_epochs": [1, 2],
        },
        "genesis": hex(&request_id(&vault_id, b"genesis", &[])),
        "enroll_device": hex(&request_id(&vault_id, b"enroll", &device)),
        "remove_device_into_epoch": hex(&request_id(&vault_id, b"remove", &[&device[..], &epoch.to_be_bytes()].concat())),
        "cancel_pending_enrollment": hex(&request_id(&vault_id, b"cancel", &pending)),
        "grant_device_epochs": hex(&request_id(&vault_id, b"grant", &grant)),
    });
    frozen("control-request-ids.json", &made);
}
