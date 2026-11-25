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
pub struct IdleLock(StdMutex<(u64, Option<JoinHandle<()>>)>);

/// Locks the vault once `milliseconds` have passed, in place of what was
/// handed over before; without it, arms a native backstop timer at the
/// device's configured auto-lock limit so a stalled window cannot disable
/// locking. `turn` is a strictly monotonic counter ordering the window's calls,
/// which can arrive out of order: one older than or equal to the last is
/// ignored. Not on the main thread, which a window closing holds.
#[tauri::command(async)]
pub fn lock_when_idle<R: Runtime>(app: AppHandle<R>, milliseconds: Option<u64>, turn: u64) {
    hand_over(&app, milliseconds.map(Duration::from_millis), turn);
}

fn max_wait<R: Runtime>(app: &AppHandle<R>) -> Duration {
    let minutes = crate::settings::read(&app.state::<AppState>().path).auto_lock_minutes;
    Duration::from_secs(u64::from(minutes) * 60)
}

fn spawn_lock_timer<R: Runtime>(app: &AppHandle<R>, after: Duration) -> JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(after).await;
        if crate::lock_everything(&app.state::<AppState>()).await {
            let _ = app.emit("vault-locked", "idle");
        }
    })
}

/// Arms (or refreshes) the native backstop idle timer at the configured
/// auto-lock limit, e.g. right after unlock or changing the auto-lock setting.
pub(crate) fn arm_backstop<R: Runtime>(app: &AppHandle<R>) {
    let Some(idle) = app.try_state::<IdleLock>() else {
        return;
    };
    let after = max_wait(app);
    let mut waiting = idle
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lock) = waiting.1.take() {
        lock.abort();
    }
    waiting.1 = Some(spawn_lock_timer(app, after));
}

pub(crate) fn hand_over<R: Runtime>(app: &AppHandle<R>, after: Option<Duration>, turn: u64) {
    let idle = app.state::<IdleLock>();
    let cap = max_wait(app);
    let mut waiting = idle
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if turn == 0 || turn <= waiting.0 {
        return;
    }
    waiting.0 = turn;
    if let Some(lock) = waiting.1.take() {
        lock.abort();
    }
    // Always clamp to the configured auto-lock setting, and keep a native
    // backstop armed even when `after` is `None` (window visible).
    let effective = match after {
        Some(after) => after.min(cap),
        None => cap,
    };
    waiting.1 = Some(spawn_lock_timer(app, effective));
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
        let unlocked = || async { state.vault.lock().await.as_ref().unwrap().is_unlocked() };
        state
            .vault
            .lock()
            .await
            .as_mut()
            .unwrap()
            .unlock("device password")
            .unwrap();

        // Taken back before it ran out, as the window shown again does:
        // replaced by the native backstop timer (5 minutes by default).
        hand_over(app.handle(), Some(Duration::from_millis(200)), 1);
        hand_over(app.handle(), None, 2);
        // A call made before (or with the same turn as) the last, arriving
        // after it, changes nothing.
        hand_over(app.handle(), Some(Duration::from_millis(100)), 1);
        hand_over(app.handle(), Some(Duration::from_millis(100)), 2);
        hand_over(app.handle(), Some(Duration::from_millis(100)), 0);
        // The native backstop handle stays armed even after `None`.
        assert!(app.state::<IdleLock>().0.lock().unwrap().1.is_some());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(unlocked().await);
        assert!(heard.lock().unwrap().is_empty());

        // Handed over again, it replaces the time before, and runs out.
        hand_over(app.handle(), Some(Duration::from_secs(60)), 3);
        hand_over(app.handle(), Some(Duration::from_millis(100)), 4);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!unlocked().await);
        assert_eq!(*heard.lock().unwrap(), ["\"idle\""]);
    }
}
