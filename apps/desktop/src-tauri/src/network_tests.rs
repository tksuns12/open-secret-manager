//! Two desktop shells, each with its own vault and peer store, pair and sync
//! over localhost through the real commands and events. The mock runtime
//! stands in for the webview; the network code is the shipped code.

use std::{
    path::Path,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use osm_vault_core::{Item, Vault};
use tauri::{
    test::{mock_builder, mock_context, noop_assets, MockRuntime},
    App, AppHandle, Listener, Manager,
};
use tokio::sync::Mutex;

use crate::{network, AppState};

fn shell(dir: &Path) -> App<MockRuntime> {
    let path = dir.join("vault.sqlite3");
    let network = network::Network::open(&path).unwrap();
    mock_builder()
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            path,
            network,
        })
        .build(mock_context(noop_assets()))
        .unwrap()
}

type Seen = Arc<StdMutex<Vec<String>>>;

fn record(app: &App<MockRuntime>, event: &str) -> Seen {
    let seen = Seen::default();
    let sink = seen.clone();
    app.listen_any(event, move |event| {
        sink.lock().unwrap().push(event.payload().to_owned());
    });
    seen
}

async fn first(seen: &Seen) -> String {
    for _ in 0..600 {
        if let Some(payload) = seen.lock().unwrap().first().cloned() {
            return payload;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("event never arrived");
}

async fn titles(app: &AppHandle<MockRuntime>) -> Vec<String> {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    let mut titles: Vec<String> = vault
        .as_ref()
        .unwrap()
        .list()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

/// Polls until `app` lists exactly `expected`, failing after a minute.
async fn eventually(app: &AppHandle<MockRuntime>, expected: &[&str]) {
    for _ in 0..600 {
        if titles(app).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(titles(app).await, expected);
}

async fn put(app: &AppHandle<MockRuntime>, title: &str) {
    let state = app.state::<AppState>();
    let mut vault = state.vault.lock().await;
    vault.as_mut().unwrap().put(Item::new(title)).unwrap();
}

#[test]
fn two_desktop_shells_pair_and_sync() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (app_a, app_b) = (shell(dir_a.path()), shell(dir_b.path()));
    let codes = record(&app_a, "pairing-code");
    let finished = record(&app_a, "pairing-finished");
    let (a, b) = (app_a.handle().clone(), app_b.handle().clone());

    tauri::async_runtime::block_on(async move {
        {
            let state = a.state::<AppState>();
            let (mut vault, _) = Vault::create(&state.path, "inviter password").unwrap();
            vault.put(Item::new("Shared")).unwrap();
            *state.vault.lock().await = Some(vault);
        }

        // Invite on A, join on B; the owner sees the same code on both.
        let invitation = network::start_invite(a.state(), a.clone()).await.unwrap();
        let joining = network::join_start(invitation.code.clone(), b.state())
            .await
            .unwrap();
        assert_eq!(first(&codes).await, format!("\"{}\"", joining.sas));
        network::confirm_invite(true, a.state()).await.unwrap();
        network::join_finish("joiner password".into(), b.state(), b.clone())
            .await
            .unwrap();
        assert!(first(&finished).await.contains("\"paired\":true"));

        // B's first sync copies the vault, and tells A where B listens.
        eventually(&b, &["Shared"]).await;

        // A change on A reaches B through the automatic sync after an edit.
        put(&a, "Added on A").await;
        network::schedule_sync(&a);
        eventually(&b, &["Added on A", "Shared"]).await;

        // And a change on B reaches A.
        put(&b, "Added on B").await;
        network::schedule_sync(&b);
        eventually(&a, &["Added on A", "Added on B", "Shared"]).await;

        // B is locked: it still receives, but only stages ciphertext.
        b.state::<AppState>()
            .vault
            .lock()
            .await
            .as_mut()
            .unwrap()
            .lock();
        put(&a, "While B was locked").await;
        network::sync_now(a.clone()).await.unwrap();
        {
            let state = b.state::<AppState>();
            let mut vault = state.vault.lock().await;
            let vault = vault.as_mut().unwrap();
            assert_eq!(vault.staged_revision_ids().unwrap().len(), 1);
            vault.unlock("joiner password").unwrap();
            assert_eq!(vault.process_staged().unwrap().applied, 1);
        }
        assert_eq!(
            titles(&b).await,
            ["Added on A", "Added on B", "Shared", "While B was locked"]
        );
    });
}
