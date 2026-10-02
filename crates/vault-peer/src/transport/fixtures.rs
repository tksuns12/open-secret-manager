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
    AddressBook, EnrollmentGrant, Peer, PeerStore,
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

/// Writes a peer store as this build makes one: a new TLS identity, an
/// address seen for a member, and the one device an older build may have
/// paired with.
#[test]
#[ignore = "writes a new fixture; it refuses to replace one"]
fn write_the_peer_store_fixture() {
    let destination = folder().join("peers.sqlite3");
    assert!(!destination.exists(), "a frozen file is never made again");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.sqlite3");
    let mut peers = PeerStore::open(&path).unwrap();
    let identity = peers.transport_identity().unwrap();
    peers.insert_legacy_peer(&legacy_peer()).unwrap();
    drop(peers);
    let book = AddressBook::open(&path).unwrap();
    book.observe(device_id_from_bytes(counting(0xa0)), "192.0.2.11:47821");
    drop(book);
    std::fs::copy(&path, &destination).unwrap();
    std::fs::write(
        folder().join("peers.json"),
        serde_json::to_string_pretty(&json!({
            "about": "What a reader should find in peers.sqlite3 beside this file. Its TLS key identifies no real device.",
            "transport_pin": hex(&identity.pin()),
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
    std::fs::write(
        folder().join("SHA256SUMS"),
        format!(
            "{}  peers.sqlite3\n",
            hex(&Sha256::digest(std::fs::read(&destination).unwrap()))
        ),
    )
    .unwrap();
}

/// A copy of the frozen peer store that a test may open.
fn copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.sqlite3");
    std::fs::copy(folder().join("peers.sqlite3"), &path).unwrap();
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

#[tokio::test]
async fn the_frozen_peer_store_still_identifies_its_device_over_tls() {
    let sums = std::fs::read_to_string(folder().join("SHA256SUMS")).unwrap();
    let (sum, name) = sums.trim_end().split_once("  ").unwrap();
    assert_eq!(name, "peers.sqlite3");
    assert_eq!(
        hex(&Sha256::digest(std::fs::read(folder().join(name)).unwrap())),
        sum
    );
    let expected: Value =
        serde_json::from_slice(&std::fs::read(folder().join("peers.json")).unwrap()).unwrap();

    let (_dir, path) = copy();
    let mut peers = PeerStore::open(&path).unwrap();
    let frozen = peers.transport_identity().unwrap();
    // The same identity as when it was written, not a new one.
    assert_eq!(hex(&frozen.pin()), expected["transport_pin"]);
    assert_eq!(peers.legacy_peers().unwrap(), [legacy_peer()]);
    drop(peers);
    let book = AddressBook::open(&path).unwrap();
    assert_eq!(
        book.get(device_id_from_bytes(counting(0xa0))).as_deref(),
        Some("192.0.2.11:47821")
    );

    // Its certificate and key complete a handshake with a device of this
    // build, as server and as client, each pinning the other.
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

#[test]
fn a_peer_store_marked_by_a_later_build_is_refused_and_an_unmarked_one_is_the_first_layout() {
    let (_dir, path) = copy();
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
    mark(2);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        PeerStore::open(&path),
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
    let mut peers = PeerStore::open(&path).unwrap();
    assert_eq!(
        hex(&peers.transport_identity().unwrap().pin()),
        expected["transport_pin"]
    );
    drop(peers);
    assert_eq!(version(&path), 1);
}
