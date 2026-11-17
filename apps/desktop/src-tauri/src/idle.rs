//! The lock for want of activity while the window is hidden or covered.
//! The window keeps the time without input while it is in view; hidden,
//! its timers can run late, so it hands the rest of that time here, and
//! takes it back when it is shown again. Run out, the vault locks and the
//! window is told so, as when the owner goes away (`away`).

use std::sync::Mutex as StdMutex;
use std::time::Duration;

use tauri::{async_runtime::JoinHandle, AppHandle, Emitter, Manager, Runtime};

use crate::AppState;

/// The lock waiting for the time handed over, if one is, and the turn of
/// the last call.
#[derive(Default)]
pub struct IdleLock(StdMutex<(f64, Option<JoinHandle<()>>)>);

/// Locks the vault once `milliseconds` have passed, in place of what was
/// handed over before; without it, only takes that back. `turn` orders the
/// window's calls (the time it made each, in milliseconds), which can
/// arrive out of order: one older than the last is ignored. Not on the main
/// thread, which a window closing holds.
#[tauri::command(async)]
pub fn lock_when_idle<R: Runtime>(app: AppHandle<R>, milliseconds: Option<u64>, turn: f64) {
    hand_over(&app, milliseconds.map(Duration::from_millis), turn);
}

pub(crate) fn hand_over<R: Runtime>(app: &AppHandle<R>, after: Option<Duration>, turn: f64) {
    let idle = app.state::<IdleLock>();
    let mut waiting = idle
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if turn < waiting.0 {
        return;
    }
    waiting.0 = turn;
    if let Some(lock) = waiting.1.take() {
        lock.abort();
    }
    let Some(after) = after else { return };
    let app = app.clone();
    waiting.1 = Some(tauri::async_runtime::spawn(async move {
        tokio::time::sleep(after).await;
        if crate::lock_everything(&app.state::<AppState>()).await {
            let _ = app.emit("vault-locked", "idle");
        }
    }));
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
    async fn the_time_handed_over_locks_the_vault_unless_it_is_taken_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite3");
        Vault::create(&path, "device password").unwrap();
        let network =
            network::Network::open(&path, std::sync::Arc::new(osm_vault_peer::NoKeystore)).unwrap();
        let app = mock_builder()
            .manage(IdleLock::default())
            .manage(AppState {
                vault: Mutex::new(Vault::open(&path).ok()),
                archive: Mutex::new(None),
                browser: browser::Browser::open(&path),
                path,
                network,
                chosen_backup: std::sync::Mutex::new(None),
                import: Mutex::new(None),
                rows_seen: crate::rows_seen::Checkpoint::new(std::sync::Arc::new(
                    crate::rows_seen::MemoryRowsSeen::default(),
                )),
            })
            .build(mock_context(noop_assets()))
            .unwrap();
        let heard = Arc::new(StdMutex::new(Vec::new()));
        let sink = heard.clone();
        app.listen_any("vault-locked", move |event| {
            sink.lock().unwrap().push(event.payload().to_owned())
        });
        let state = app.state::<AppState>();
        let unlocked = || async { state.vault.lock().await.as_ref().unwrap().is_unlocked() };
        state
            .vault
            .lock()
            .await
            .as_mut()
            .unwrap()
            .unlock("device password")
            .unwrap();

        // Taken back before it ran out, as the window shown again does.
        hand_over(app.handle(), Some(Duration::from_millis(200)), 1.0);
        hand_over(app.handle(), None, 2.0);
        // A call made before the last, arriving after it, changes nothing.
        hand_over(app.handle(), Some(Duration::from_millis(100)), 1.5);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(unlocked().await);
        assert!(heard.lock().unwrap().is_empty());

        // Handed over again, it replaces the time before, and runs out.
        hand_over(app.handle(), Some(Duration::from_secs(60)), 3.0);
        hand_over(app.handle(), Some(Duration::from_millis(100)), 4.0);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!unlocked().await);
        assert_eq!(*heard.lock().unwrap(), ["\"idle\""]);
    }
}
