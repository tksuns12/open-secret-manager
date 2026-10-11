//! The frozen answer to a join request, and a frozen peer store: the file
//! that holds a device's TLS identity, which has to keep identifying the
//! device to the others under every later build.

use std::sync::Arc;

use osm_vault_membership::device_id_from_bytes;
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;
use crate::{
    fixture::{counting, folder, frozen, hex, sent, unhex},
    AddressBook, EnrollmentGrant, KeyKept, MemoryKeystore, NoKeystore, Peer, PeerStore,
};

#[test]
fn the_answers_to_a_join_request_are_the_frozen_ones() {
    // The grant frozen with the other pairing messages, inside its answer.
    let pairing: Value =
        serde_json::from_slice(&std::fs::read(folder().join("pairing.json")).unwrap()).unwrap();
    let grant: EnrollmentGrant = crate::wire::decode_body(&unhex(
        pairing["enrollment_grant"]["sent"]["body"]
            .as_str()
            .unwrap(),
    ))
    .unwrap();
    let made = json!({
        "about": "What the inviter answers a join request with, as this code made it when the formats were frozen: postcard, in a frame of a 4-byte big-endian length and the body. The grant is the one in pairing.json.",
        "declined": sent(&PairingReply::Declined),
        "enrollment": sent(&PairingReply::Enrollment(grant)),
        "refused": sent(&PairingReply::Refused),
    });
    let frozen = frozen("pairing-replies.json", &made);
    let body = |name: &str| unhex(frozen[name]["body"].as_str().unwrap());
    assert_eq!(body("declined"), [0]);
    assert_eq!(body("refused"), [2]);
    let read: PairingReply = crate::wire::decode_body(&body("enrollment")).unwrap();
    assert!(
        matches!(read, PairingReply::Enrollment(grant) if grant.request_id() == counting::<16>(0xe0))
    );
    assert!(crate::wire::decode_body::<PairingReply>(&[3]).is_err());
}

fn legacy_peer() -> Peer {
    Peer {
        device_id: counting(0x40),
        public_key: counting(0x60),
        transport_pin: counting(0x20),
        address: Some("192.0.2.10:47820".into()),
        paired_at: 1_750_000_000,
    }
}

/// Writes a peer store as this build makes one, with no keystore, so that
/// its TLS key is kept in the file and any later build can read it: a new
/// TLS identity, an address seen for a member, and the one device an older
/// build may have paired with. `peers.sqlite3` was written by this test as
/// it was before Phase 14, in the first layout; `peers-2.sqlite3` by this
/// one, in the second.
#[test]
#[ignore = "writes a new fixture; it refuses to replace one"]
fn write_the_peer_store_fixture() {
    let destination = folder().join("peers-2.sqlite3");
    assert!(!destination.exists(), "a frozen file is never made again");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.sqlite3");
    let mut peers = PeerStore::open(&path, Arc::new(NoKeystore)).unwrap();
    let identity = peers.transport_identity().unwrap();
    peers.insert_legacy_peer(&legacy_peer()).unwrap();
    drop(peers);
    let book = AddressBook::open(&path).unwrap();
    book.observe(device_id_from_bytes(counting(0xa0)), "192.0.2.11:47821");
    drop(book);
    std::fs::copy(&path, &destination).unwrap();
    std::fs::write(
        folder().join("peers-2.json"),
        serde_json::to_string_pretty(&json!({
            "about": "What a reader should find in peers-2.sqlite3 beside this file: the second layout, with the TLS key kept in the file because no keystore sealed it. Its TLS key identifies no real device.",
            "transport_pin": hex(&identity.pin()),
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
    let mut sums = std::fs::read_to_string(folder().join("SHA256SUMS")).unwrap();
    sums.push_str(&format!(
        "{}  peers-2.sqlite3\n",
        hex(&Sha256::digest(std::fs::read(&destination).unwrap()))
    ));
    std::fs::write(folder().join("SHA256SUMS"), sums).unwrap();
}

/// The frozen peer stores, each with what a reader should find in it.
const FROZEN: [(&str, &str); 2] = [
    ("peers.sqlite3", "peers.json"),
    ("peers-2.sqlite3", "peers-2.json"),
];

/// A copy of a frozen peer store that a test may open.
fn copy(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.sqlite3");
    std::fs::copy(folder().join(name), &path).unwrap();
    (dir, path)
}

#[derive(Debug)]
struct Only([u8; 32]);

impl PinPolicy for Only {
    fn accepts(&self, pin: &[u8; 32]) -> bool {
        *pin == self.0
    }
}

/// A TLS handshake in memory. Returns the pin of the certificate the server
/// saw, if both ends completed it.
async fn handshake(
    server: &TransportIdentity,
    accepts: [u8; 32],
    client: &TransportIdentity,
    pinned: [u8; 32],
) -> Option<[u8; 32]> {
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(
        server_config(server, ClientPolicy::Members(Arc::new(Only(accepts)))).unwrap(),
    );
    let connector = TlsConnector::from(client_config(client, pinned).unwrap());
    let (accepted, connected) = tokio::join!(
        acceptor.accept(server_end),
        connector.connect(server_name(), client_end)
    );
    let (accepted, connected) = (accepted.ok()?, connected.ok()?);
    assert_eq!(
        connected.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let seen = accepted.get_ref().1.peer_certificates()?.first()?.clone();
    Some(crate::peers::pin_of(&seen))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn the_frozen_peer_stores_still_identify_their_device_over_tls_and_are_sealed_when_opened() {
    let sums = std::fs::read_to_string(folder().join("SHA256SUMS")).unwrap();
    let sums: Vec<(&str, &str)> = sums
        .lines()
        .map(|line| line.split_once("  ").unwrap())
        .collect();
    assert_eq!(
        sums.iter().map(|(_, name)| *name).collect::<Vec<_>>(),
        FROZEN.map(|(name, _)| name)
    );
    for (sum, name) in &sums {
        assert_eq!(
            hex(&Sha256::digest(std::fs::read(folder().join(name)).unwrap())),
            *sum,
            "{name}"
        );
    }

    for (name, about) in FROZEN {
        let expected: Value =
            serde_json::from_slice(&std::fs::read(folder().join(about)).unwrap()).unwrap();

        // Opened where there is no keystore, it is read as it is.
        let (_dir, path) = copy(name);
        let mut peers = PeerStore::open(&path, Arc::new(NoKeystore)).unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::InFile), "{name}");
        let unsealed = peers.transport_identity().unwrap();
        drop(peers);
        let secret = crate::peers::tests::secret(&unsealed);
        assert!(contains(&std::fs::read(&path).unwrap(), &secret), "{name}");

        // Opened with a keystore, its key is sealed, and is no longer in
        // the file anywhere.
        let keystore = Arc::new(MemoryKeystore::default());
        let (_dir, path) = copy(name);
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::Sealed), "{name}");
        assert_eq!(keystore.len(), 1);
        let frozen = peers.transport_identity().unwrap();
        // The same identity as when it was written, not a new one.
        assert_eq!(hex(&frozen.pin()), expected["transport_pin"], "{name}");
        assert_eq!(frozen.private_key, unsealed.private_key);
        assert_eq!(peers.legacy_peers().unwrap(), [legacy_peer()]);
        drop(peers);
        assert!(!contains(&std::fs::read(&path).unwrap(), &secret), "{name}");
        let book = AddressBook::open(&path).unwrap();
        assert_eq!(
            book.get(device_id_from_bytes(counting(0xa0))).as_deref(),
            Some("192.0.2.11:47821")
        );
        drop(book);
        // Opened again, it is opened by the keystore.
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert_eq!(peers.transport_identity().unwrap().pin(), frozen.pin());
        assert_eq!(keystore.len(), 1);
        drop(peers);

        // Its certificate and key complete a handshake with a device of
        // this build, as server and as client, each pinning the other.
        let other = PeerStore::open_in_memory()
            .unwrap()
            .transport_identity()
            .unwrap();
        assert_eq!(
            handshake(&frozen, other.pin(), &other, frozen.pin()).await,
            Some(other.pin())
        );
        assert_eq!(
            handshake(&other, frozen.pin(), &frozen, other.pin()).await,
            Some(frozen.pin())
        );
        // A pin that is not its certificate's fails, either way round.
        assert_eq!(handshake(&frozen, other.pin(), &other, [0; 32]).await, None);
        assert_eq!(
            handshake(&frozen, [0; 32], &other, frozen.pin()).await,
            None
        );
    }
}

#[test]
fn a_peer_store_marked_by_a_later_build_is_refused_and_an_unmarked_one_is_the_first_layout() {
    let (_dir, path) = copy("peers.sqlite3");
    let version = |path: &std::path::Path| -> u32 {
        Connection::open(path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    };
    let mark = |mark: u32| {
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", mark)
            .unwrap();
    };
    assert_eq!(version(&path), 1);
    mark(3);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        PeerStore::open(&path, Arc::new(NoKeystore)),
        Err(Error::Sync(osm_vault_sync::Error::UnsupportedVersion))
    ));
    assert!(matches!(
        AddressBook::open(&path),
        Err(Error::Sync(osm_vault_sync::Error::UnsupportedVersion))
    ));
    assert!(std::fs::read(&path).unwrap() == before);

    // A store from before the mark says nothing, and is taken as it is.
    mark(0);
    let expected: Value =
        serde_json::from_slice(&std::fs::read(folder().join("peers.json")).unwrap()).unwrap();
    let mut peers = PeerStore::open(&path, Arc::new(NoKeystore)).unwrap();
    assert_eq!(
        hex(&peers.transport_identity().unwrap().pin()),
        expected["transport_pin"]
    );
    drop(peers);
    assert_eq!(version(&path), 2);
}

#[test]
fn a_first_layout_store_whose_number_the_address_book_raised_first_is_still_moved_over() {
    // The address book shares the file and marks it too; a store it opened
    // first carries the second layout's number over the first layout's key.
    let (_dir, path) = copy("peers.sqlite3");
    drop(AddressBook::open(&path).unwrap());
    let expected: Value =
        serde_json::from_slice(&std::fs::read(folder().join("peers.json")).unwrap()).unwrap();
    let mut peers = PeerStore::open(&path, Arc::new(MemoryKeystore::default())).unwrap();
    assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::Sealed));
    assert_eq!(
        hex(&peers.transport_identity().unwrap().pin()),
        expected["transport_pin"]
    );
}

proptest::proptest! {
    /// Any bytes read as the answer to a join request are refused, or are
    /// the one form of an answer.
    #[test]
    fn any_bytes_are_refused_or_are_the_one_form_of_an_answer(
        body in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..300),
    ) {
        if let Ok(reply) = crate::wire::decode_body::<PairingReply>(&body) {
            proptest::prop_assert_eq!(&crate::wire::encode_frame(&reply).unwrap()[4..], body.as_slice());
        }
    }
}
