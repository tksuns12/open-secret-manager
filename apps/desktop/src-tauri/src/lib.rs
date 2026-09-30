#![forbid(unsafe_code)]

use std::{path::PathBuf, sync::Mutex};

use osm_vault_core::{ItemSummary, PasswordPolicy, Vault};
use serde::Serialize;
use zeroize::Zeroizing;

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
            unlock_vault
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
