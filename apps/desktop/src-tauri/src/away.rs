//! Locking when the owner's session goes away from the app: the computer
//! going to sleep, the displays sleeping, the screen locking, the screen
//! saver starting, or another user taking the screen. The window's own
//! timer and its being covered are the interface's to watch; these the
//! system tells the app, on macOS and, through logind, on Linux.

use osm_desktop_session::Away;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::AppState;

pub fn start<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    osm_desktop_session::watch(move |away| {
        let app = app.clone();
        // Called on the main thread (on Linux, on a thread of the session
        // crate's), which must not wait for the vault: a command holding it
        // may be waiting for the main thread.
        tauri::async_runtime::spawn(async move { went_away(&app, away).await });
    });
}

/// Locks everything and takes a copied secret off the clipboard. Tells the
/// interface why, if anything was open.
pub(crate) async fn went_away<R: Runtime>(app: &AppHandle<R>, away: Away) {
    osm_desktop_session::clear_last_secret();
    if crate::lock_everything(&app.state::<AppState>()).await {
        let _ = app.emit("vault-locked", away.as_str());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use osm_vault_core::Vault;
    use tauri::{
        test::{mock_builder, mock_context, noop_assets},
        Listener,
    };
    use tokio::sync::Mutex;

    use super::*;
    use crate::{browser, network};

    #[tokio::test]
    async fn the_session_going_away_locks_the_vault_and_says_why_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite3");
        Vault::create(&path, "device password").unwrap();
        let network = network::Network::open(&path).unwrap();
        let app = mock_builder()
            .manage(AppState {
                vault: Mutex::new(Vault::open(&path).ok()),
                archive: Mutex::new(None),
                browser: browser::Browser::open(&path),
                path,
                network,
                chosen_backup: std::sync::Mutex::new(None),
                import: Mutex::new(None),
            })
            .build(mock_context(noop_assets()))
            .unwrap();
        let heard = Arc::new(StdMutex::new(Vec::new()));
        let sink = heard.clone();
        app.listen_any("vault-locked", move |event| {
            sink.lock().unwrap().push(event.payload().to_owned())
        });
        let state = app.state::<AppState>();
        state
            .vault
            .lock()
            .await
            .as_mut()
            .unwrap()
            .unlock("device password")
            .unwrap();

        went_away(app.handle(), Away::ScreenLocked).await;
        assert!(!state.vault.lock().await.as_ref().unwrap().is_unlocked());
        assert_eq!(*heard.lock().unwrap(), ["\"screen_locked\""]);

        // Nothing was open the second time: nothing to say.
        went_away(app.handle(), Away::Sleep).await;
        assert_eq!(heard.lock().unwrap().len(), 1);
    }
}
