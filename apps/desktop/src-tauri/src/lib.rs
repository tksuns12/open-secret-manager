#![forbid(unsafe_code)]

use std::{path::PathBuf, sync::Mutex};

use osm_vault_core::{Item, ItemKind, ItemSummary, PasswordPolicy, Vault, VaultItem};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

struct AppState {
    vault: Mutex<Option<Vault>>,
    path: PathBuf,
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
            _ => "vault_error",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[tauri::command]
fn vault_status(state: tauri::State<'_, AppState>) -> &'static str {
    match state
        .vault
        .lock()
        .ok()
        .and_then(|vault| vault.as_ref().map(Vault::is_unlocked))
    {
        Some(true) => "unlocked",
        Some(false) => "locked",
        None => "missing",
    }
}

#[tauri::command]
fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
    if let Some(vault) = vault.as_mut() {
        vault.lock();
    }
    Ok(())
}

#[tauri::command]
fn list_entries(state: tauri::State<'_, AppState>) -> Result<Vec<ItemSummary>, CommandError> {
    let vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
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
    let mut policy = PasswordPolicy::default();
    policy.length = length;
    osm_vault_core::generate_password(&policy).map_err(Into::into)
}

#[tauri::command]
fn copy_totp(id: String, state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
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
fn get_entry(id: String, state: tauri::State<'_, AppState>) -> Result<EntryDetail, CommandError> {
    let vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
    let vault = vault.as_ref().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let VaultItem { item, revision } = vault.get(&id)?;
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
fn create_entry(
    mut input: EntryInput,
    state: tauri::State<'_, AppState>,
) -> Result<ItemSummary, CommandError> {
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    let mut item = Item::default();
    input.apply_to(&mut item);
    let id = item.id.clone();
    vault.put(item)?;
    Ok(vault.get(&id)?.into())
}

#[tauri::command]
fn update_entry(
    id: String,
    expected_revision: String,
    mut input: EntryInput,
    state: tauri::State<'_, AppState>,
) -> Result<ItemSummary, CommandError> {
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "locked",
        message: "vault is locked".into(),
    })?;
    // Start from the stored item so fields the form does not show (custom
    // fields, tags) are preserved.
    let VaultItem { mut item, .. } = vault.get(&id)?;
    input.apply_to(&mut item);
    vault.update(item, &expected_revision)?;
    Ok(vault.get(&id)?.into())
}

#[tauri::command]
fn create_vault(
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, CommandError> {
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
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
    let (created, recovery) = Vault::create(&state.path, &password).map_err(CommandError::from)?;
    *vault = Some(created);
    Ok(recovery.to_string())
}

#[tauri::command]
fn unlock_vault(password: String, state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "state",
        message: "vault state unavailable".into(),
    })?;
    let vault = vault.as_mut().ok_or_else(|| CommandError {
        code: "vault_missing",
        message: "vault has not been configured".into(),
    })?;
    vault.unlock(&password).map_err(Into::into)
}

pub fn run() {
    let path = default_vault_path();
    tauri::Builder::default()
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            path,
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
            update_entry
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
