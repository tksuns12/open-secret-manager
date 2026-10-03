#![forbid(unsafe_code)]

mod archive;
#[cfg(unix)]
mod browser;
#[cfg(not(unix))]
#[path = "browser_unsupported.rs"]
mod browser;
#[cfg(all(test, unix))]
mod browser_tests;
mod network;
#[cfg(test)]
mod network_tests;

use std::path::PathBuf;

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

#[tauri::command]
async fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().await;
    if let Some(vault) = vault.as_mut() {
        vault.lock();
    }
    // An opened archived copy is unlocked too: locking closes it.
    *state.archive.lock().await = None;
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
    let mut clipboard = arboard::Clipboard::new().map_err(|_| CommandError {
        code: "clipboard",
        message: "operating-system clipboard is unavailable".into(),
    })?;
    clipboard
        .set_text(code.as_str())
        .map_err(|_| CommandError {
            code: "clipboard",
            message: "operating-system clipboard is unavailable".into(),
        })?;
    let expected = Zeroizing::new(code.to_string());
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(30));
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
async fn update_entry(
    id: String,
    expected_revision: String,
    mut input: EntryInput,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
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
    let this_device = vault.device_id();
    Ok(vault
        .versions(&id)?
        .into_iter()
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
            device: version.author_device_id[..4]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            this_device: Some(version.author_device_id) == this_device,
            revision: version.revision,
        })
        .collect())
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

pub fn run() {
    let path = default_vault_path();
    network::finish_interrupted_recovery(&path);
    let network = network::Network::open(&path).expect("could not open the peer store");
    let browser = browser::Browser::open(&path);
    tauri::Builder::default()
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            archive: Mutex::new(None),
            path,
            network,
            browser,
        })
        .setup(|app| {
            network::start(app.handle());
            browser::start(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            lock_vault,
            list_entries,
            generate_password,
            copy_totp,
            create_vault,
            unlock_vault,
            get_entry,
            create_entry,
            update_entry,
            list_versions,
            resolve_entry,
            list_held,
            accept_held,
            discard_held,
            recovery_status,
            pending_recovery_key,
            confirm_recovery_key,
            enable_recovery,
            network::sync_status,
            network::sync_now,
            network::devices,
            network::found_control_plane,
            network::remove_device,
            network::cancel_enrollment,
            network::recover_vault,
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
            browser::disconnect_browser
        ])
        .run(tauri::generate_context!())
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
        item
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
