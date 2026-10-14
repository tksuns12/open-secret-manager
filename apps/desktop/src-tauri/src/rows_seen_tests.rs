//! An earlier copy of the vault's file put in its place, found at the next
//! unlock from what this computer kept, outside the file, of what the file
//! held: through the real commands on the mock runtime, with the keystore
//! in memory and outliving each run of the app, as the system's does.

use std::{path::Path, sync::Arc};

use tauri::Manager;

use crate::{
    lock_vault, network,
    network_tests::{put, shell_keeping, titles, PASSWORD},
    rows_seen::{self, MemoryRowsSeen},
    unlock_vault, AppState,
};

/// One run of the app on `dir`, keeping its counts in `rows`: `run` is given
/// the app's handle, and the app is stopped after it, locked or not.
async fn run_app<F, T>(dir: &Path, rows: &Arc<MemoryRowsSeen>, run: F) -> T
where
    F: AsyncFnOnce(&tauri::AppHandle<tauri::test::MockRuntime>) -> T,
{
    let app = shell_keeping(dir, rows.clone());
    let handle = app.handle().clone();
    let result = run(&handle).await;
    network::shutdown(&handle).await;
    drop(app);
    result
}

async fn unlock(app: &tauri::AppHandle<tauri::test::MockRuntime>) {
    unlock_vault(PASSWORD.into(), app.state(), app.clone())
        .await
        .unwrap();
}

async fn lock(app: &tauri::AppHandle<tauri::test::MockRuntime>) {
    lock_vault(app.state()).await.unwrap();
}

async fn told(app: &tauri::AppHandle<tauri::test::MockRuntime>) -> bool {
    crate::rows_changed(app.state()).await.unwrap()
}

async fn sealed_rows(app: &tauri::AppHandle<tauri::test::MockRuntime>) -> u64 {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    vault.as_ref().unwrap().sealed_rows().unwrap()
}

/// The vault and a copy of its file, kept once a first run made a vault
/// with one item and locked it.
async fn a_vault_and_its_copy(dir: &Path, copy: &Path, rows: &Arc<MemoryRowsSeen>) {
    run_app(dir, rows, async |app| {
        crate::create_vault(PASSWORD.into(), app.state(), app.clone())
            .await
            .unwrap();
        put(app, "Kept").await;
        lock(app).await;
    })
    .await;
    std::fs::copy(dir.join("vault.sqlite3"), copy).unwrap();
}

#[test]
fn an_earlier_copy_of_the_file_put_back_is_said_until_the_owner_confirms_it() {
    let (dir, elsewhere) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (dir, copy) = (dir.path(), elsewhere.path().join("earlier.sqlite3"));
    let rows = Arc::new(MemoryRowsSeen::default());
    tauri::async_runtime::block_on(async {
        a_vault_and_its_copy(dir, &copy, &rows).await;

        // Later runs add two items: one kept up with after it was written,
        // as every write of the owner's is, and one at the lock.
        let seen = run_app(dir, &rows, async |app| {
            unlock(app).await;
            assert!(!told(app).await);
            put(app, "Later").await;
            rows_seen::keep_up(app).await;
            put(app, "Later still").await;
            let seen = sealed_rows(app).await;
            lock(app).await;
            seen
        })
        .await;

        // The copy put back: its own seal holds, but it holds less than this
        // computer saw. That is said at each unlock until the owner confirms.
        std::fs::copy(&copy, dir.join("vault.sqlite3")).unwrap();
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            assert!(sealed_rows(app).await < seen);
            assert!(told(app).await);
            assert_eq!(titles(app).await, ["Kept"]);
            lock(app).await;
            unlock(app).await;
            assert!(told(app).await);
            crate::confirm_rows_changed(app.state()).await.unwrap();
            assert!(!told(app).await);
            lock(app).await;
        })
        .await;

        // Confirmed, the file is taken as it is.
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            assert!(!told(app).await);
        })
        .await;
    });
}

#[test]
fn an_app_stopped_before_it_kept_up_with_its_writes_says_nothing() {
    let (dir, elsewhere) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (dir, copy) = (dir.path(), elsewhere.path().join("earlier.sqlite3"));
    let rows = Arc::new(MemoryRowsSeen::default());
    tauri::async_runtime::block_on(async {
        a_vault_and_its_copy(dir, &copy, &rows).await;
        // Written, then stopped while unlocked: what was kept is behind.
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            put(app, "Written last").await;
        })
        .await;
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            assert!(!told(app).await);
            assert_eq!(titles(app).await, ["Kept", "Written last"]);
        })
        .await;
    });
}

#[test]
fn without_a_keystore_nothing_is_kept_and_an_unlock_says_nothing() {
    let (dir, elsewhere) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (dir, copy) = (dir.path(), elsewhere.path().join("earlier.sqlite3"));
    let rows = Arc::new(MemoryRowsSeen::default());
    rows.set_unavailable();
    tauri::async_runtime::block_on(async {
        a_vault_and_its_copy(dir, &copy, &rows).await;
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            put(app, "Later").await;
            lock(app).await;
        })
        .await;
        std::fs::copy(&copy, dir.join("vault.sqlite3")).unwrap();
        run_app(dir, &rows, async |app| {
            unlock(app).await;
            assert!(!told(app).await);
            assert_eq!(titles(app).await, ["Kept"]);
        })
        .await;
    });
}
