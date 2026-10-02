//! The frozen formats of this crate: an epoch-key envelope as it is stored
//! in the control plane's log and state, and how an invitation's token is
//! kept. `fixtures/vectors.txt` holds inputs and what this code made of
//! them when the formats were frozen. The file is never made again; to add
//! one for a new format, run the ignored test while it does not exist.

use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    open_epoch_key, seal_epoch_key, DeviceId, EpochKeyEnvelope, Error, HpkeKeyPair,
    InvitationToken, VaultId,
};

fn file() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vectors.txt")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// `N` bytes counting up from `first`: inputs anyone can write down.
fn counting<const N: usize>(first: u8) -> [u8; N] {
    std::array::from_fn(|index| first.wrapping_add(index as u8))
}

/// The `name = value` lines of the frozen file.
fn frozen() -> BTreeMap<String, String> {
    std::fs::read_to_string(file())
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(" = ").unwrap();
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

const EPOCH: u64 = 3;

fn inputs() -> (VaultId, DeviceId, [u8; 32], [u8; 32], [u8; 32]) {
    (
        VaultId(counting(0x10)),
        // A device is named here by its signing key.
        DeviceId(counting(0x50)),
        // The secret the recipient's key pair is derived from.
        counting(0x30),
        // The epoch key that is sealed.
        counting(0xa0),
        // An invitation's token.
        counting(0x70),
    )
}

#[test]
#[ignore = "writes a new fixture; it refuses to replace one"]
fn write_the_vectors() {
    assert!(!file().exists(), "a frozen file is never made again");
    let (vault, recipient, secret, epoch_key, token) = inputs();
    let pair = HpkeKeyPair::from_secret(&secret);
    let envelope = seal_epoch_key(vault, EPOCH, recipient, pair.public(), &epoch_key).unwrap();
    let lines = [
        "# Inputs and what the sync code made of them when the formats were frozen.".to_owned(),
        "# Bytes are lowercase hexadecimal. The keys are counting patterns and protect".to_owned(),
        "# nothing. The envelope is HPKE (RFC 9180) base mode with DHKEM(X25519,".to_owned(),
        "# HKDF-SHA256), HKDF-SHA256, and AES-256-GCM, info osm-epoch-key-hpke-v1; its".to_owned(),
        "# sender's key is random, so it is sealed once and only opened afterwards.".to_owned(),
        format!("vault_id = {}", hex(&vault.0)),
        format!("epoch = {EPOCH}"),
        format!("recipient_device = {}", hex(&recipient.0)),
        format!("recipient_secret = {}", hex(&secret)),
        format!("recipient_public_key = {}", hex(&pair.public().as_bytes())),
        format!("epoch_key = {}", hex(&epoch_key)),
        format!("envelope = {}", hex(&envelope.to_bytes())),
        format!("invitation_token = {}", hex(&token)),
        format!(
            "invitation_token_stored_as = {}",
            hex(&InvitationToken::from_bytes(token).digest())
        ),
    ];
    std::fs::write(file(), lines.join("\n") + "\n").unwrap();
}

#[test]
fn the_frozen_envelope_opens_and_is_laid_out_as_documented() {
    let frozen = frozen();
    let (vault, recipient, secret, epoch_key, _) = inputs();
    for (name, input) in [
        ("vault_id", vault.0),
        ("recipient_device", recipient.0),
        ("recipient_secret", secret),
        ("epoch_key", epoch_key),
    ] {
        assert_eq!(frozen[name], hex(&input), "{name}");
    }

    // The recipient's key pair comes from its secret the same way.
    let pair = HpkeKeyPair::from_secret(&secret);
    assert_eq!(
        hex(&pair.public().as_bytes()),
        frozen["recipient_public_key"]
    );

    // The envelope is its fields one after another, each of a fixed length.
    let bytes = unhex(&frozen["envelope"]);
    assert_eq!(bytes.len(), 188);
    assert_eq!(&bytes[..4], b"OSK1");
    assert_eq!(bytes[4..36], vault.0);
    assert_eq!(bytes[36..44], EPOCH.to_be_bytes());
    assert_eq!(bytes[44..76], recipient.0);
    assert_eq!(bytes[76..108], pair.public().as_bytes());
    let envelope = EpochKeyEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(envelope.to_bytes().as_slice(), bytes);
    assert_eq!(envelope.epoch(), EPOCH);

    // It opens for the recipient, and only as what it says it is.
    let opened = open_epoch_key(&envelope, vault, EPOCH, recipient, pair.private()).unwrap();
    assert_eq!(*opened, epoch_key);
    assert!(open_epoch_key(
        &envelope,
        VaultId([0; 32]),
        EPOCH,
        recipient,
        pair.private()
    )
    .is_err());
    assert!(open_epoch_key(&envelope, vault, EPOCH + 1, recipient, pair.private()).is_err());
    assert!(open_epoch_key(&envelope, vault, EPOCH, DeviceId([0; 32]), pair.private()).is_err());
    let other = HpkeKeyPair::from_secret(&counting(0x31));
    assert!(matches!(
        open_epoch_key(&envelope, vault, EPOCH, recipient, other.private()),
        Err(Error::InvalidPrivateKey)
    ));

    // A changed bit anywhere in it is refused, as is a byte more or less.
    for position in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[position] ^= 1;
        let opened = EpochKeyEnvelope::from_bytes(&changed)
            .and_then(|changed| open_epoch_key(&changed, vault, EPOCH, recipient, pair.private()));
        assert!(opened.is_err(), "byte {position}");
    }
    assert!(EpochKeyEnvelope::from_bytes(&bytes[..187]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(EpochKeyEnvelope::from_bytes(&longer).is_err());
}

#[test]
fn an_invitations_token_is_kept_as_the_frozen_hash() {
    let frozen = frozen();
    let (_, _, _, _, token) = inputs();
    assert_eq!(frozen["invitation_token"], hex(&token));
    assert_eq!(
        hex(&InvitationToken::from_bytes(token).digest()),
        frozen["invitation_token_stored_as"]
    );
}
