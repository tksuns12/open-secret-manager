//! The pairing listener over real TLS connections on localhost.

use std::{path::Path, time::Duration};

use osm_vault_core::Vault;
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;

use crate::{
    invite, start_pairing, Error, Invitation, MemberContact, PairingListener, PeerStore, Voting,
};

const NOW: u64 = 1_800_000_000;

struct Device {
    vault: Vault,
    invitations: InvitationStore,
    peers: PeerStore,
}

fn device(path: &Path) -> Device {
    let (vault, _) = Vault::create(path, "password").unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: PeerStore::open_in_memory().unwrap(),
    }
}

async fn pairing_listener(peers: &mut PeerStore) -> (PairingListener, String) {
    let listener = PairingListener::bind("127.0.0.1:0", peers).await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    (listener, address)
}

fn invitation(device: &mut Device, address: &str) -> Invitation {
    invite(
        &device.vault,
        &mut device.invitations,
        &mut device.peers,
        vec![address.to_owned()],
        NOW,
        300,
    )
    .unwrap()
}

#[tokio::test]
async fn the_pairing_listener_ignores_junk_and_the_joiner_hears_a_refusal() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let (listener, address) = pairing_listener(&mut a.peers).await;

    // The owner declines.
    let invited = invitation(&mut a, &address);
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let (served, joined) = tokio::join!(
        async {
            let pending = listener
                .next_request()
                .await?
                .review(
                    &a.vault,
                    &a.invitations,
                    &mut a.peers,
                    Voting::Votes,
                    None,
                    NOW,
                )?
                .complete()
                .await?;
            pending.decline().await
        },
        async {
            // Plain-text junk first; the listener must keep waiting.
            let mut junk = tokio::net::TcpStream::connect(&address).await.unwrap();
            junk.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            drop(junk);
            let connection = start_pairing(invited, &mut b_peers, NOW).await?;
            connection.receive_enrollment().await.map(|_| ())
        }
    );
    served.unwrap();
    assert!(matches!(joined, Err(Error::NotConfirmed)));

    // The owner confirms, but the vault's devices do not accept the
    // enrollment: the joiner is told that, not left waiting.
    let invited = invitation(&mut a, &address);
    let members = vec![MemberContact {
        device_id: a.vault.device_id().unwrap(),
        transport_pin: a.peers.transport_identity().unwrap().pin(),
        address: None,
    }];
    let (served, joined) = tokio::join!(
        async {
            let pending = listener
                .next_request()
                .await?
                .review(
                    &a.vault,
                    &a.invitations,
                    &mut a.peers,
                    Voting::Votes,
                    None,
                    NOW,
                )?
                .complete()
                .await?;
            let (_, approved) = pending.approve_enrollment(
                &a.vault,
                &mut a.invitations,
                members,
                Voting::Votes,
                None,
                NOW,
            )?;
            approved.refuse().await
        },
        async {
            let connection = start_pairing(invited, &mut b_peers, NOW).await?;
            connection.receive_enrollment().await.map(|_| ())
        }
    );
    served.unwrap();
    assert!(matches!(joined, Err(Error::EnrollmentRefused)));
}

#[tokio::test]
async fn a_slow_socket_does_not_block_a_legitimate_joiner() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let (listener, address) = pairing_listener(&mut a.peers).await;
    let invited = invitation(&mut a, &address);
    let mut b_peers = PeerStore::open_in_memory().unwrap();

    // Hold open a silent TCP socket that never sends TLS bytes.
    let _stalled = tokio::net::TcpStream::connect(&address).await.unwrap();

    let started = std::time::Instant::now();
    let (served, joined) = tokio::join!(
        async {
            let pending = listener
                .next_request()
                .await?
                .review(
                    &a.vault,
                    &a.invitations,
                    &mut a.peers,
                    Voting::Votes,
                    None,
                    NOW,
                )?
                .complete()
                .await?;
            let sas = pending.sas();
            pending.decline().await?;
            Ok::<_, Error>(sas)
        },
        async {
            let connection = start_pairing(invited, &mut b_peers, NOW).await?;
            let sas = connection.sas();
            let _ = connection.receive_enrollment().await;
            Ok::<_, Error>(sas)
        }
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(served.unwrap(), joined.unwrap());
}

#[tokio::test]
async fn a_v1_join_request_is_refused_on_the_live_wire() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let (listener, address) = pairing_listener(&mut a.peers).await;
    let inviter_pin = a.peers.transport_identity().unwrap().pin();
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let b_identity = b_peers.transport_identity().unwrap();

    let frozen: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/pairing.json")).unwrap();
    let v1_frame = crate::fixture::unhex(frozen["join_request"]["sent"]["frame"].as_str().unwrap());

    let connector = tokio_rustls::TlsConnector::from(crate::transport::client_config_for_tests(
        &b_identity,
        inviter_pin,
    ));
    let (server, client) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(500), listener.next_request()),
        async {
            let tcp = tokio::net::TcpStream::connect(&address).await.unwrap();
            let mut stream = connector
                .connect(crate::transport::server_name_for_tests(), tcp)
                .await
                .unwrap();
            stream.write_all(&v1_frame).await.unwrap();
            let mut buf = [0u8; 16];
            // Server must drop the v1 wire request rather than issuing a challenge.
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap_or(0);
            n
        }
    );
    assert!(server.is_err(), "v1 JoinRequest must never be accepted");
    assert_eq!(client, 0);
}

#[tokio::test]
async fn a_joiner_refuses_an_inviter_whose_certificate_does_not_match() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let mut impostor = device(&dir.path().join("c.db"));
    let (impostor_listener, address) = pairing_listener(&mut impostor.peers).await;
    // A's invitation, but its address leads to another device.
    let invited = invitation(&mut a, &address);
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let (_, joined) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), impostor_listener.next_request()),
        start_pairing(invited, &mut b_peers, NOW)
    );
    assert!(matches!(joined, Err(Error::PinMismatch)));
}

/// Two devices on one machine must not both listen on one port: the second
/// is refused, and a caller then asks for any free port. (Windows once let
/// the second bind beside the first, and connections went to the wrong one.)
#[tokio::test]
async fn a_port_in_use_is_not_shared() {
    let first = crate::listen(0).unwrap();
    let port = first.local_addr().unwrap().port();
    let second = crate::listen(port);
    assert_eq!(
        second.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::AddrInUse)
    );
    // Any free port is still there to be had.
    let other = crate::listen(0).unwrap();
    assert_ne!(other.local_addr().unwrap().port(), port);
}

#[tokio::test]
async fn pairing_listener_rejects_mismatched_and_revoked_tokens() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let (listener, address) = pairing_listener(&mut a.peers).await;

    // Issue two invitations; bind the listener strictly to the second token
    // and revoke the first.
    let first = invitation(&mut a, &address);
    let second = invitation(&mut a, &address);
    listener.expect_token(second.token_digest());
    let mut b_peers = PeerStore::open_in_memory().unwrap();

    // Presenting `first` to a listener bound to `second` must be refused even
    // before `first` is revoked in the invitation store.
    let (review_err, join_res) = tokio::join!(
        async {
            listener
                .next_request()
                .await
                .unwrap()
                .review(
                    &a.vault,
                    &a.invitations,
                    &mut a.peers,
                    Voting::Votes,
                    None,
                    NOW,
                )
                .err()
        },
        start_pairing(first, &mut b_peers, NOW)
    );
    assert!(matches!(review_err, Some(Error::InvalidInvitation)));
    assert!(join_res.is_err());

    // Revoking `second` via its digest prevents it from ever being accepted on
    // any listener.
    assert!(a
        .invitations
        .revoke_by_digest(&second.token_digest(), NOW)
        .unwrap());
    let (review_err, join_res) = tokio::join!(
        async {
            listener
                .next_request()
                .await
                .unwrap()
                .review(
                    &a.vault,
                    &a.invitations,
                    &mut a.peers,
                    Voting::Votes,
                    None,
                    NOW,
                )
                .err()
        },
        start_pairing(second, &mut b_peers, NOW)
    );
    assert!(review_err.is_some());
    assert!(join_res.is_err());
}
