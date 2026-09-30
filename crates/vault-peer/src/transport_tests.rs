use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use osm_vault_core::{Item, Vault};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tempfile::tempdir;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tokio_rustls::TlsConnector;

use crate::{
    accept_pairing, connect_sync, invite, serve_sync, start_pairing,
    transport::{client_config_for_tests, server_name_for_tests},
    Error, Peer, PeerStore,
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

async fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    (listener, address)
}

/// Pairs `a` with a new device over TLS on localhost, confirming on both
/// sides only if the short codes match.
async fn pair_over_tls(dir: &Path, a: &mut Device) -> Device {
    let (pairing_listener, address) = listener().await;
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        vec![address],
        NOW,
        300,
    )
    .unwrap();
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let shown_on_a = Arc::new(Mutex::new(None::<String>));
    let recorded = shown_on_a.clone();
    let (served, joined) = tokio::join!(
        accept_pairing(
            &pairing_listener,
            &mut a.vault,
            &mut a.invitations,
            &mut a.peers,
            move |sas| {
                *recorded.lock().unwrap() = Some(sas);
                async { true }
            },
            || NOW,
        ),
        async {
            let connection = start_pairing(invitation, &mut b_peers, NOW).await?;
            let sas = connection.sas();
            let (joiner, grant) = connection.receive_grant().await?;
            Ok::<_, Error>((joiner, grant, sas))
        }
    );
    served.unwrap();
    let (joiner, grant, shown_on_b) = joined.unwrap();
    assert_eq!(
        shown_on_a.lock().unwrap().as_deref(),
        Some(shown_on_b.as_str())
    );
    let vault = joiner
        .finish(
            &grant,
            true,
            dir.join("b.db"),
            "password",
            &mut b_peers,
            NOW,
        )
        .unwrap();
    Device {
        vault,
        invitations: InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
        peers: b_peers,
    }
}

#[tokio::test]
async fn devices_pair_and_sync_over_pinned_tls_in_both_directions() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let item = Item::new("Over TLS");
    a.vault.put(item.clone()).unwrap();
    let mut b = pair_over_tls(dir.path(), &mut a).await;
    assert_eq!(
        b.peers.peers().unwrap()[0].transport_pin,
        a.peers.transport_identity().unwrap().pin()
    );
    assert_eq!(
        a.peers.peers().unwrap()[0].transport_pin,
        b.peers.transport_identity().unwrap().pin()
    );

    // A serves, B dials.
    let (sync_listener, address) = listener().await;
    let (served, dialed) = tokio::join!(
        serve_sync(&sync_listener, &mut a.vault, &mut a.peers),
        connect_sync(&address, &mut b.vault, &mut b.peers)
    );
    assert_eq!(served.unwrap().sent, 1);
    assert_eq!(dialed.unwrap().applied, 1);
    assert_eq!(b.vault.get(&item.id).unwrap().item.title, "Over TLS");

    // B edits, then B serves and A dials over a new connection.
    let current = b.vault.get(&item.id).unwrap();
    let mut edited = current.item.clone();
    edited.title = "Edited on B".into();
    b.vault.update(edited, &current.revision).unwrap();
    let (sync_listener, address) = listener().await;
    let (served, dialed) = tokio::join!(
        serve_sync(&sync_listener, &mut b.vault, &mut b.peers),
        connect_sync(&address, &mut a.vault, &mut a.peers)
    );
    served.unwrap();
    assert_eq!(dialed.unwrap().applied, 1);
    assert_eq!(a.vault.get(&item.id).unwrap().item.title, "Edited on B");
}

#[tokio::test]
async fn certificates_other_than_the_pinned_one_are_refused_by_both_sides() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let mut b = pair_over_tls(dir.path(), &mut a).await;

    // C knows A's pin, but A never paired with C: A refuses C's certificate.
    let mut c = device(&dir.path().join("c.db"));
    c.peers
        .add(&Peer {
            device_id: [9; 16],
            public_key: a.vault.device_public_key().unwrap(),
            transport_pin: a.peers.transport_identity().unwrap().pin(),
            address: None,
            paired_at: NOW,
        })
        .unwrap();
    let (sync_listener, address) = listener().await;
    let (served, dialed) = tokio::join!(
        serve_sync(&sync_listener, &mut a.vault, &mut a.peers),
        connect_sync(&address, &mut c.vault, &mut c.peers)
    );
    assert!(matches!(served, Err(Error::PinMismatch)));
    assert!(dialed.is_err());

    // B dials what it thinks is A but reaches C: B refuses C's certificate
    // before sending anything.
    let (sync_listener, address) = listener().await;
    let (served, dialed) = tokio::join!(
        serve_sync(&sync_listener, &mut c.vault, &mut c.peers),
        connect_sync(&address, &mut b.vault, &mut b.peers)
    );
    assert!(matches!(dialed, Err(Error::PinMismatch)));
    assert!(served.is_err());
    assert!(b.vault.list().unwrap().is_empty());
}

#[tokio::test]
async fn an_oversized_frame_over_tls_ends_the_session() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let mut b = pair_over_tls(dir.path(), &mut a).await;
    let identity = b.peers.transport_identity().unwrap();
    let a_pin = a.peers.transport_identity().unwrap().pin();

    let (sync_listener, address) = listener().await;
    let (served, _) = tokio::join!(
        serve_sync(&sync_listener, &mut a.vault, &mut a.peers),
        async {
            let connector = TlsConnector::from(client_config_for_tests(&identity, a_pin));
            let tcp = tokio::net::TcpStream::connect(&address).await.unwrap();
            let mut stream = connector
                .connect(server_name_for_tests(), tcp)
                .await
                .unwrap();
            // A length prefix far beyond the limit, and nothing else.
            stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    );
    assert!(matches!(served, Err(Error::FrameTooLarge)));
}

#[tokio::test]
async fn the_pairing_listener_ignores_junk_and_the_owner_can_decline() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let (pairing_listener, address) = listener().await;
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        vec![address.clone()],
        NOW,
        300,
    )
    .unwrap();
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let (served, joined) = tokio::join!(
        accept_pairing(
            &pairing_listener,
            &mut a.vault,
            &mut a.invitations,
            &mut a.peers,
            |_| async { false },
            || NOW,
        ),
        async {
            // Plain-text junk first; the listener must keep waiting.
            let mut junk = tokio::net::TcpStream::connect(&address).await.unwrap();
            junk.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            drop(junk);
            let connection = start_pairing(invitation, &mut b_peers, NOW).await?;
            connection.receive_grant().await.map(|_| ())
        }
    );
    assert!(matches!(served, Err(Error::NotConfirmed)));
    assert!(matches!(joined, Err(Error::NotConfirmed)));
    assert!(a.peers.peers().unwrap().is_empty());
    assert!(b_peers.peers().unwrap().is_empty());
}

#[tokio::test]
async fn a_joiner_refuses_an_inviter_whose_certificate_does_not_match() {
    let dir = tempdir().unwrap();
    let mut a = device(&dir.path().join("a.db"));
    let mut impostor = device(&dir.path().join("c.db"));
    let (impostor_listener, address) = listener().await;
    // A's invitation, but its address leads to another device.
    let invitation = invite(
        &a.vault,
        &mut a.invitations,
        &mut a.peers,
        vec![address],
        NOW,
        300,
    )
    .unwrap();
    let mut b_peers = PeerStore::open_in_memory().unwrap();
    let (_, joined) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(2),
            accept_pairing(
                &impostor_listener,
                &mut impostor.vault,
                &mut impostor.invitations,
                &mut impostor.peers,
                |_| async { true },
                || NOW,
            ),
        ),
        start_pairing(invitation, &mut b_peers, NOW)
    );
    assert!(matches!(joined, Err(Error::PinMismatch)));
    assert!(b_peers.peers().unwrap().is_empty());
}
