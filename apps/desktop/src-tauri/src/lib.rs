#![forbid(unsafe_code)]

mod archive;
mod away;
mod backup;
#[cfg(test)]
mod backup_tests;
#[cfg(unix)]
mod browser;
#[cfg(not(unix))]
#[path = "browser_unsupported.rs"]
mod browser;
#[cfg(all(test, unix))]
mod browser_tests;
mod history;
mod import;
#[cfg(test)]
mod import_tests;
mod network;
#[cfg(test)]
mod network_tests;
mod settings;

use std::path::{Path, PathBuf};

use osm_vault_core::{Item, ItemKind, ItemSummary, PasswordPolicy, Vault, VaultItem};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// Lock order, where more than one is needed: `vault`, then `archive`,
/// then the network's invitation store, then its peer store. Network waits
/// (handshakes, the owner reading a pairing code) never hold any of them.
/// The browser session's own locks are taken last and never held across a
/// wait.
struct AppState {
    vault: Mutex<Option<Vault>>,
    /// A copy of a vault put away earlier that the owner has opened.
    archive: Mutex<Option<archive::Opened>>,
    path: PathBuf,
    network: network::Network,
    /// Where a request from a browser waits for the owner.
    browser: browser::Browser,
    /// The backup the owner picked to restore, until it is restored.
    chosen_backup: std::sync::Mutex<Option<PathBuf>>,
    /// What an export the owner chose would add, until the import is
    /// confirmed or dropped. Locking drops it.
    import: Mutex<Option<osm_vault_core::ImportPreview>>,
}

#[derive(Debug, Serialize)]
struct CommandError {
    code: &'static str,
    message: String,
}

impl From<osm_vault_core::Error> for CommandError {
    fn from(error: osm_vault_core::Error) -> Self {
        let code = match error {
            osm_vault_core::Error::Locked => "locked",
            osm_vault_core::Error::InvalidCredentials => "invalid_credentials",
            osm_vault_core::Error::NotFound => "not_found",
            osm_vault_core::Error::Conflict { .. } => "conflict",
            osm_vault_core::Error::InvalidItem(_) => "invalid_item",
            osm_vault_core::Error::Unresolved => "unresolved",
            osm_vault_core::Error::MissingParent => "missing_parent",
            osm_vault_core::Error::InvalidRecoveryKey => "invalid_recovery_key",
            osm_vault_core::Error::RecoveryNotEnabled => "recovery_not_enabled",
            osm_vault_core::Error::UpgradeRequiresPassword => "upgrade_requires_password",
            osm_vault_core::Error::InvalidImport(_) => "invalid_import",
            _ => "vault_error",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[tauri::command]
async fn vault_status(state: tauri::State<'_, AppState>) -> Result<&'static str, CommandError> {
    Ok(
        match state.vault.lock().await.as_ref().map(Vault::is_unlocked) {
            Some(true) => "unlocked",
            Some(false) => "locked",
            None => "missing",
        },
    )
}

/// Locks the vault and closes an opened archived copy, which is unlocked
/// too. Says whether either was open.
async fn lock_everything(state: &AppState) -> bool {
    let mut vault = state.vault.lock().await;
    let unlocked = vault.as_ref().is_some_and(Vault::is_unlocked);
    if let Some(vault) = vault.as_mut() {
        vault.lock();
    }
    let archive = state.archive.lock().await.take();
    state.import.lock().await.take();
    unlocked || archive.is_some()
}

/// Why the vault file on this device cannot be opened, if one is here and
/// cannot be: damaged, written by a later version, or not a vault.
#[tauri::command]
async fn vault_problem(state: tauri::State<'_, AppState>) -> Result<Option<String>, CommandError> {
    let vault = state.vault.lock().await;
    if vault.is_some() || state.path.symlink_metadata().is_err() {
        return Ok(None);
    }
    Ok(Vault::open(&state.path)
        .err()
        .map(|error| error.to_string()))
}

#[tauri::command]
async fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    lock_everything(&state).await;
    Ok(())
}

#[tauri::command]
async fn list_entries(state: tauri::State<'_, AppState>) -> Result<Vec<ItemSummary>, CommandError> {
    let vault = state.vault.lock().await;
    vault
        .as_ref()
        .ok_or_else(|| CommandError {
            code: "locked",
            message: "vault is locked".into(),
        })?
        .list()
        .map_err(Into::into)
}

#[tauri::command]
fn generate_password(length: usize) -> Result<String, CommandError> {
    let policy = PasswordPolicy {
        length,
        ..PasswordPolicy::default()
    };
    osm_vault_core::generate_password(&policy).map_err(Into::into)
}

#[tauri::command]
async fn copy_totp(id: String, state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommandError {
            code: "clock",
            message: "system clock is before the Unix epoch".into(),
        })?
        .as_secs();
    let code = Zeroizing::new(
        vault
            .item_totp_code(&id, unix_time)
            .map_err(CommandError::from)?,
    );
    copy_for_a_while(&code)
}

/// Copies an item's password, for 30 seconds.
#[tauri::command]
async fn copy_password(id: String, state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let item = vault.get(&id)?.item;
    if item.password.is_empty() {
        return Err(CommandError {
            code: "no_password",
            message: "the item has no password".into(),
        });
    }
    copy_for_a_while(&item.password)
}

/// Copies the value of one of an item's other fields, for 30 seconds.
#[tauri::command]
async fn copy_field(
    id: String,
    name: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let item = vault.get(&id)?.item;
    let value = item.custom_fields.get(&name).ok_or_else(|| CommandError {
        code: "not_found",
        message: "the item has no such field".into(),
    })?;
    copy_for_a_while(value)
}

/// Puts a secret on the clipboard and takes it off 30 seconds later, unless
/// something else was put there since. On macOS and Linux the entry asks
/// clipboard history apps to leave it out (on macOS it also stays on this
/// Mac), and locking takes it off too.
fn copy_for_a_while(secret: &str) -> Result<(), CommandError> {
    let unavailable = || CommandError {
        code: "clipboard",
        message: "operating-system clipboard is unavailable".into(),
    };
    const WHILE: std::time::Duration = std::time::Duration::from_secs(30);
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let copied = osm_desktop_session::copy_secret(secret).ok_or_else(unavailable)?;
        std::thread::spawn(move || {
            std::thread::sleep(WHILE);
            osm_desktop_session::clear_if_unchanged(copied);
        });
        return Ok(());
    }
    let mut clipboard = arboard::Clipboard::new().map_err(|_| unavailable())?;
    clipboard.set_text(secret).map_err(|_| unavailable())?;
    let expected = Zeroizing::new(secret.to_owned());
    std::thread::spawn(move || {
        std::thread::sleep(WHILE);
        let Ok(mut clipboard) = arboard::Clipboard::new() else {
            return;
        };
        if clipboard.get_text().ok().as_deref() == Some(expected.as_str()) {
            let _ = clipboard.clear();
        }
    });
    Ok(())
}

/// Editable fields returned to the interface. The stored password and TOTP
/// secret never cross the bridge; the form only learns whether they are set.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryDetail {
    id: String,
    title: String,
    kind: ItemKind,
    username: String,
    url: String,
    notes: String,
    favorite: bool,
    has_password: bool,
    has_totp: bool,
    /// The names of the item's other fields, such as an imported card's
    /// number; their values are copied, never sent to the window.
    fields: Vec<String>,
    revision: String,
}

/// Form input for create and edit. `password` and `totp_secret` are `None`
/// to keep the stored value; an empty `totp_secret` removes it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryInput {
    title: String,
    kind: ItemKind,
    username: String,
    url: String,
    notes: String,
    favorite: bool,
    password: Option<String>,
    totp_secret: Option<String>,
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        self.username.zeroize();
        self.notes.zeroize();
        self.password.zeroize();
        self.totp_secret.zeroize();
    }
}

impl EntryInput {
    fn apply_to(&mut self, item: &mut Item) {
        item.title = std::mem::take(&mut self.title);
        item.kind = self.kind;
        item.username = std::mem::take(&mut self.username);
        item.url = std::mem::take(&mut self.url);
        item.notes = std::mem::take(&mut self.notes);
        item.favorite = self.favorite;
        if let Some(password) = self.password.take() {
            item.password = password;
        }
        if let Some(secret) = self.totp_secret.take() {
            let secret = Zeroizing::new(secret);
            item.totp_secret = (!secret.trim().is_empty()).then(|| secret.trim().to_owned());
        }
    }
}

#[tauri::command]
async fn get_entry(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<EntryDetail, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let VaultItem { item, revision, .. } = vault.get(&id)?;
    Ok(EntryDetail {
        id: item.id.clone(),
        title: item.title.clone(),
        kind: item.kind,
        username: item.username.clone(),
        url: item.url.clone(),
        notes: item.notes.clone(),
        favorite: item.favorite,
        has_password: !item.password.is_empty(),
        has_totp: item.totp_secret.is_some(),
        fields: item.custom_fields.keys().cloned().collect(),
        revision,
    })
}

#[tauri::command]
async fn create_entry(
    mut input: EntryInput,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ItemSummary, CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let mut item = Item::default();
    input.apply_to(&mut item);
    let id = item.id.clone();
    vault.put(item)?;
    network::schedule_sync(&app);
    Ok(vault.get(&id)?.into())
}

#[tauri::command]
async fn update_entry<R: tauri::Runtime>(
    id: String,
    expected_revision: String,
    mut input: EntryInput,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<ItemSummary, CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    // Start from the stored item so fields the form does not show (custom
    // fields, tags) are preserved.
    let VaultItem { mut item, .. } = vault.get(&id)?;
    input.apply_to(&mut item);
    vault.update(item, &expected_revision)?;
    network::schedule_sync(&app);
    Ok(vault.get(&id)?.into())
}

/// Deletes an item on every device, as read at `expected_revision`. Its
/// earlier versions stay in the vault's history and in backups.
#[tauri::command]
async fn delete_entry<R: tauri::Runtime>(
    id: String,
    expected_revision: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    vault.delete(&id, &expected_revision)?;
    network::schedule_sync(&app);
    Ok(())
}

/// One side of a conflict as shown to the owner. Secrets stay in Rust; the
/// kept version's password and TOTP secret are copied there on resolve.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionSummary {
    revision: String,
    deleted: bool,
    title: String,
    username: String,
    url: String,
    /// Short hex prefix of the author device ID.
    device: String,
    this_device: bool,
    /// The fields in which this version differs from the others, by name
    /// only: what the title, username, and website shown do not tell.
    differs: Vec<&'static str>,
}

/// The versions of an item in conflict, as the owner reviews them.
fn version_summaries(
    versions: Vec<osm_vault_core::ItemVersion>,
    this_device: Option<[u8; 16]>,
) -> Vec<VersionSummary> {
    let differs = |item: &Item| {
        let mut names = Vec::new();
        for other in versions.iter().filter_map(|other| other.item.as_ref()) {
            for name in item.changed_from(other) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        names
    };
    versions
        .iter()
        .map(|version| VersionSummary {
            deleted: version.item.is_none(),
            title: version
                .item
                .as_ref()
                .map(|item| item.title.clone())
                .unwrap_or_default(),
            username: version
                .item
                .as_ref()
                .map(|item| item.username.clone())
                .unwrap_or_default(),
            url: version
                .item
                .as_ref()
                .map(|item| item.url.clone())
                .unwrap_or_default(),
            device: history::short_device(&version.author_device_id),
            this_device: Some(version.author_device_id) == this_device,
            differs: version.item.as_ref().map(differs).unwrap_or_default(),
            revision: version.revision.clone(),
        })
        .collect()
}

#[tauri::command]
async fn list_versions(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<VersionSummary>, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    Ok(version_summaries(vault.versions(&id)?, vault.device_id()))
}

/// Resolves a conflict by keeping one of the versions the owner reviewed.
/// `heads` is the set that was shown, so a version that arrived since stays
/// visible instead of being silently discarded.
#[tauri::command]
async fn resolve_entry(
    id: String,
    keep_revision: String,
    heads: Vec<String>,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    if !heads.contains(&keep_revision) {
        return Err(CommandError {
            code: "invalid_item",
            message: "the kept version must be one of the reviewed versions".into(),
        });
    }
    let kept = vault
        .versions(&id)?
        .into_iter()
        .find(|version| version.revision == keep_revision)
        .ok_or(osm_vault_core::Error::Conflict {
            expected: keep_revision,
            actual: "<superseded>".into(),
        })?;
    vault.resolve(&id, kept.item, &heads)?;
    network::schedule_sync(&app);
    Ok(())
}

/// A change held for the owner's review: one written by a device that is
/// not, or is no longer, one of the vault's devices. Secrets stay in Rust;
/// the interface learns only whether they differ from what is here now.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeldChange {
    revision: String,
    /// Short hex prefix of the author device ID.
    device: String,
    /// The author is a device that was removed from the vault and the
    /// change verifies as its own. Otherwise this device does not know who
    /// wrote it.
    removed_device: bool,
    /// `new`, `edit`, `delete`, or `restore`: an edit of an item that is
    /// deleted here.
    change: &'static str,
    /// The held version's fields, or for a deletion the item's as it is
    /// here now.
    title: String,
    username: String,
    url: String,
    /// For an edit: what differs from the item as it is here now.
    changed: Vec<&'static str>,
}

fn changed_fields(held: &Item, current: &Item) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let mut note = |differs: bool, name| {
        if differs {
            changed.push(name);
        }
    };
    note(held.title != current.title, "title");
    note(held.username != current.username, "username");
    note(held.password != current.password, "password");
    note(held.url != current.url, "website");
    note(held.totp_secret != current.totp_secret, "one-time code");
    note(held.notes != current.notes, "notes");
    note(
        held.kind != current.kind
            || held.favorite != current.favorite
            || held.custom_fields != current.custom_fields
            || held.tags != current.tags,
        "other details",
    );
    changed
}

#[tauri::command]
async fn list_held(state: tauri::State<'_, AppState>) -> Result<Vec<HeldChange>, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let mut changes = Vec::new();
    for held in vault.quarantined()? {
        let current = match vault.get(&held.item_id) {
            Ok(current) => Some(current.item),
            Err(osm_vault_core::Error::NotFound) => None,
            Err(error) => return Err(error.into()),
        };
        let change = match (&held.item, &current) {
            (None, _) => "delete",
            (Some(_), Some(_)) => "edit",
            (Some(_), None) if held.parents.is_empty() => "new",
            (Some(_), None) => "restore",
        };
        let shown = held.item.as_ref().or(current.as_ref());
        let field = |pick: fn(&Item) -> &String| shown.map(pick).cloned().unwrap_or_default();
        changes.push(HeldChange {
            device: held.author_device_id[..4]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            removed_device: held.known_author,
            change,
            title: field(|item| &item.title),
            username: field(|item| &item.username),
            url: field(|item| &item.url),
            changed: match (&held.item, &current) {
                (Some(held), Some(current)) => changed_fields(held, current),
                _ => Vec::new(),
            },
            revision: held.revision,
        });
    }
    Ok(changes)
}

/// Keeps a held change. It becomes part of the vault as a change made by
/// this device and reaches the other devices at the next sync. If the item
/// was edited since, it becomes a second version to review.
#[tauri::command]
async fn accept_held<R: tauri::Runtime>(
    revision: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    vault.accept_quarantined(&revision)?;
    network::schedule_sync(&app);
    Ok(())
}

/// Rejects a held change: the item stays as it is on this device. For a
/// change by a removed device, the other devices follow at the next sync.
#[tauri::command]
async fn discard_held<R: tauri::Runtime>(
    revision: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    if vault.discard_quarantined(&revision)?.is_some() {
        network::schedule_sync(&app);
    }
    Ok(())
}

#[tauri::command]
async fn create_vault<R: tauri::Runtime>(
    password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<String, CommandError> {
    // Wiped when dropped. The copies the bridge made on the way are beyond
    // reach.
    let password = Zeroizing::new(password);
    let recovery = {
        let mut vault = state.vault.lock().await;
        if vault.is_some() {
            return Err(CommandError {
                code: "vault_exists",
                message: "vault is already configured".into(),
            });
        }
        if let Some(parent) = state.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| CommandError {
                code: "storage",
                message: error.to_string(),
            })?;
        }
        let (mut created, recovery) =
            Vault::create(&state.path, &password).map_err(CommandError::from)?;
        // Kept in the vault until the owner confirms having stored it, in
        // case the app stops before the key has been shown.
        let _ = created.keep_recovery_key_until_confirmed(&recovery);
        *vault = Some(created);
        recovery.to_string()
    };
    network::after_create(&app).await;
    Ok(recovery)
}

#[tauri::command]
async fn unlock_vault<R: tauri::Runtime>(
    password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle<R>,
) -> Result<(), CommandError> {
    let password = Zeroizing::new(password);
    {
        let mut vault = state.vault.lock().await;
        let vault = vault.as_mut().ok_or_else(|| CommandError {
            code: "vault_missing",
            message: "vault has not been configured".into(),
        })?;
        vault.unlock(&password)?;
    }
    // The vault is brought in line with committed membership before
    // anything received while locked is verified; then this device catches
    // up with the others.
    network::after_unlock(&app).await;
    Ok(())
}

/// Whether this device can be unlocked with the recovery key. A device that
/// joined from another one starts without it.
#[tauri::command]
async fn recovery_status(state: tauri::State<'_, AppState>) -> Result<bool, CommandError> {
    Ok(state
        .vault
        .lock()
        .await
        .as_ref()
        .is_some_and(Vault::recovery_enabled))
}

/// The recovery key of a vault made on this device that the owner has not
/// yet confirmed storing. It is shown after each unlock until then.
#[tauri::command]
async fn pending_recovery_key(
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    Ok(vault
        .unconfirmed_recovery_key()?
        .map(|recovery| recovery.to_string()))
}

/// Whether the last unlock found records taken out of the vault's file
/// that the owner has not yet been told of.
#[tauri::command]
async fn rows_changed(state: tauri::State<'_, AppState>) -> Result<bool, CommandError> {
    let vault = state.vault.lock().await;
    Ok(vault
        .as_ref()
        .is_some_and(|vault| vault.is_unlocked() && vault.rows_changed()))
}

/// The owner has seen that records were taken out: stop saying so.
#[tauri::command]
async fn confirm_rows_changed(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    if let Some(vault) = vault.as_mut() {
        vault.confirm_rows_changed()?;
    }
    Ok(())
}

/// The owner has stored the recovery key: the vault stops keeping it.
#[tauri::command]
async fn confirm_recovery_key(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    if let Some(vault) = vault.as_mut() {
        vault.confirm_recovery_key_stored()?;
    }
    Ok(())
}

/// Turns on recovery for this device after checking the typed key against
/// the vault's recovery check.
#[tauri::command]
async fn enable_recovery(
    recovery_key: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let recovery_key = Zeroizing::new(recovery_key);
    let recovery = osm_vault_core::RecoveryKey::parse(recovery_key.trim())?;
    let mut vault = state.vault.lock().await;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    vault.enable_recovery(&recovery).map_err(Into::into)
}

/// Why the app could not start on this computer's files, if it could not.
struct StartupProblem(Option<String>);

/// For the window, before anything else: why the app could not start, in
/// place of the vault, or nothing when it started.
#[tauri::command]
fn startup_problem(state: tauri::State<'_, StartupProblem>) -> Option<String> {
    state.0.clone()
}

/// The window alone, saying why the app cannot start on the files beside
/// the vault: nothing else runs, and nothing is written.
fn run_refused(context: tauri::Context<tauri::Wry>, vault_path: &Path, problem: String) {
    let folder = vault_path.parent().unwrap_or(Path::new("."));
    tauri::Builder::default()
        .manage(StartupProblem(Some(format!(
            "{problem}. The files are in {}.",
            folder.display()
        ))))
        .invoke_handler(tauri::generate_handler![startup_problem])
        .run(context)
        .expect("error while running Open Secret Manager");
}

pub fn run() {
    let context = tauri::generate_context!();
    let path = default_vault_path();
    network::finish_interrupted_recovery(&path);
    let network = match network::Network::open(&path) {
        Ok(network) => network,
        Err(problem) => return run_refused(context, &path, problem.message),
    };
    let browser = browser::Browser::open(&path);
    tauri::Builder::default()
        .manage(StartupProblem(None))
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            archive: Mutex::new(None),
            path,
            network,
            browser,
            chosen_backup: std::sync::Mutex::new(None),
            import: Mutex::new(None),
        })
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            network::start(app.handle());
            browser::start(app.handle());
            away::start(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            startup_problem,
            vault_status,
            vault_problem,
            lock_vault,
            list_entries,
            generate_password,
            copy_totp,
            copy_password,
            copy_field,
            create_vault,
            unlock_vault,
            get_entry,
            create_entry,
            update_entry,
            delete_entry,
            list_versions,
            resolve_entry,
            list_held,
            accept_held,
            discard_held,
            recovery_status,
            pending_recovery_key,
            confirm_recovery_key,
            rows_changed,
            confirm_rows_changed,
            enable_recovery,
            backup::save_backup,
            backup::choose_backup,
            backup::restore_backup,
            backup::reset_password,
            network::sync_status,
            network::sync_now,
            network::devices,
            network::found_control_plane,
            network::remove_device,
            network::cancel_enrollment,
            network::recover_vault,
            network::put_unreadable_away,
            network::reset_device,
            network::leave_vault,
            network::start_invite,
            network::confirm_invite,
            network::cancel_invite,
            network::join_start,
            network::join_finish,
            network::cancel_join,
            archive::list_archives,
            archive::open_archive,
            archive::copy_from_archive,
            archive::close_archive,
            archive::delete_archive,
            browser::fill_request,
            browser::approve_fill,
            browser::deny_fill,
            browser::browser_status,
            browser::connect_browser,
            browser::disconnect_browser,
            history::item_history,
            history::deleted_entries,
            history::restore_entry,
            import::choose_import,
            import::confirm_import,
            import::cancel_import,
            settings::settings,
            settings::set_auto_lock
        ])
        .run(context)
        .expect("error while running Open Secret Manager");
}

fn default_vault_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OpenSecretManager")
        .join("vault.sqlite3")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(password: Option<&str>, totp_secret: Option<&str>) -> EntryInput {
        EntryInput {
            title: "GitHub".into(),
            kind: ItemKind::Login,
            username: "octo".into(),
            url: "https://github.com".into(),
            notes: String::new(),
            favorite: true,
            password: password.map(Into::into),
            totp_secret: totp_secret.map(Into::into),
        }
    }

    fn stored() -> Item {
        let mut item = Item::new("Old");
        item.password = "old-password".into();
        item.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        item.custom_fields.insert("pin".into(), "1234".into());
        item.tags.push("work".into());
        // A field of a later build's, which this one does not know.
        item.unknown_fields.insert(
            "passkey".into(),
            serde_json::json!({ "credential": "secret" }),
        );
        item
    }

    #[test]
    fn versions_in_conflict_say_in_which_fields_they_differ_by_name_only() {
        let here = stored();
        let mut there = stored();
        there.notes = "a note only there".into();
        there.password = "another password".into();
        let version = |item: Option<Item>, author: u8| osm_vault_core::ItemVersion {
            revision: format!("revision-{author}"),
            author_device_id: [author; 16],
            item,
        };
        let summaries = version_summaries(
            vec![
                version(Some(here), 1),
                version(Some(there), 2),
                version(None, 3),
            ],
            Some([1; 16]),
        );
        assert_eq!(summaries[0].differs, ["password", "notes"]);
        assert_eq!(summaries[1].differs, ["password", "notes"]);
        assert!(summaries[0].this_device && !summaries[1].this_device);
        // A deletion is said as such; nothing of it differs by field.
        assert!(summaries[2].deleted && summaries[2].differs.is_empty());
        // Names only: no value reaches the window.
        let sent = serde_json::to_string(&summaries).unwrap();
        assert!(!sent.contains("another password") && !sent.contains("a note only there"));
    }

    #[test]
    fn omitted_secrets_keep_stored_values() {
        let mut item = stored();
        input(None, None).apply_to(&mut item);
        assert_eq!(item.title, "GitHub");
        assert!(item.favorite);
        assert_eq!(item.password, "old-password");
        assert_eq!(item.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            item.custom_fields.get("pin").map(String::as_str),
            Some("1234")
        );
        assert_eq!(item.tags, ["work"]);
        assert_eq!(item.unknown_fields, stored().unknown_fields);
    }

    #[test]
    fn provided_secrets_replace_and_blank_totp_removes() {
        let mut item = stored();
        input(Some("new-password"), Some("  ")).apply_to(&mut item);
        assert_eq!(item.password, "new-password");
        assert_eq!(item.totp_secret, None);

        input(None, Some(" GEZDGNBVGY3TQOJQ ")).apply_to(&mut item);
        assert_eq!(item.totp_secret.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
    }

    #[test]
    fn input_deserializes_from_camel_case_bridge_payload() {
        let parsed: EntryInput = serde_json::from_str(
            r#"{"title":"Note","kind":"secure_note","username":"","url":"","notes":"x","favorite":false,"totpSecret":""}"#,
        )
        .unwrap();
        assert_eq!(parsed.kind, ItemKind::SecureNote);
        assert!(parsed.password.is_none());
        assert_eq!(parsed.totp_secret.as_deref(), Some(""));
    }
}
