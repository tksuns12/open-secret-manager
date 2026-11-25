//! Locking when the owner's session goes away from the app: the computer
//! going to sleep, the displays sleeping, the screen locking, the screen
//! saver starting, or another user taking the screen. The time without
//! input is the window's to keep, and `idle`'s while it is hidden; these
//! the system tells the app, on macOS and, through logind, on Linux.

use osm_desktop_session::Away;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::AppState;

pub fn start<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    osm_desktop_session::watch(move |away| {
        // Clear clipboard and attempt an immediate non-blocking lock on the
        // notification callback thread so keys are wiped before the OS finishes
        // suspending the process, without ever deadlocking against commands.
        osm_desktop_session::clear_last_secret();
        let locked_now = lock_try_now(&app.state::<AppState>());
        let app = app.clone();
        tauri::async_runtime::spawn(async move { went_away_after(&app, away, locked_now).await });
    });
}

fn lock_try_now(state: &AppState) -> bool {
    let mut was_open = false;
    if let Ok(mut vault) = state.vault.try_lock() {
        if let Some(vault) = vault.as_mut() {
            if vault.is_unlocked() {
                state.rows_seen.keep_up(vault);
                was_open = true;
            }
            vault.lock();
        }
    }
    if let Ok(mut archive) = state.archive.try_lock() {
        if archive.take().is_some() {
            was_open = true;
        }
    }
    if let Ok(mut import) = state.import.try_lock() {
        import.take();
    }
    was_open
}

/// Locks everything and takes a copied secret off the clipboard. Tells the
/// interface why, if anything was open.
#[cfg(test)]
pub(crate) async fn went_away<R: Runtime>(app: &AppHandle<R>, away: Away) {
    went_away_after(app, away, false).await;
}

async fn went_away_after<R: Runtime>(app: &AppHandle<R>, away: Away, already_locked: bool) {
    osm_desktop_session::clear_last_secret();
    let locked_more = crate::lock_everything(&app.state::<AppState>()).await;
    if already_locked || locked_more {
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
        let network =
            network::Network::open(&path, std::sync::Arc::new(osm_vault_peer::NoKeystore)).unwrap();
        let app = mock_builder()
            .manage(AppState {
                vault: Arc::new(Mutex::new(Vault::open(&path).ok())),
                archive: Mutex::new(None),
                browser: browser::Browser::open(&path),
                path,
                network,
                chosen_backup: std::sync::Mutex::new(None),
                import: Mutex::new(None),
                rows_seen: crate::rows_seen::Checkpoint::new(std::sync::Arc::new(
                    crate::rows_seen::MemoryRowsSeen::default(),
                )),
                health_budget: std::sync::Mutex::new(crate::HealthBudget::default()),
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
