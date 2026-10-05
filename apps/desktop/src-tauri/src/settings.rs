//! What the owner sets on this device, kept beside the vault in
//! `settings.json`: how many minutes the window waits without activity
//! before it locks the vault. Each device keeps its own; nothing here is
//! synced, and a reset of the device leaves it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{AppState, CommandError};

/// The waits the owner can choose, in minutes.
pub const AUTO_LOCK_CHOICES: [u32; 4] = [1, 5, 15, 60];
const DEFAULT_AUTO_LOCK: u32 = 5;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub auto_lock_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK,
        }
    }
}

fn file(vault: &Path) -> PathBuf {
    vault.with_file_name("settings.json")
}

/// The settings kept beside the vault at `vault`; the defaults when there
/// are none, or when what is there is not settings this app wrote.
pub fn read(vault: &Path) -> Settings {
    std::fs::read(file(vault))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
        .filter(|settings| AUTO_LOCK_CHOICES.contains(&settings.auto_lock_minutes))
        .unwrap_or_default()
}

fn write(vault: &Path, settings: &Settings) -> std::io::Result<()> {
    let path = file(vault);
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, serde_json::to_vec_pretty(settings)?)?;
    std::fs::rename(&partial, &path)
}

#[tauri::command]
pub fn settings(state: tauri::State<'_, AppState>) -> Settings {
    read(&state.path)
}

/// Sets how many minutes without activity lock the vault: one of
/// [`AUTO_LOCK_CHOICES`].
#[tauri::command]
pub fn set_auto_lock(
    minutes: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Settings, CommandError> {
    set_auto_lock_at(&state.path, minutes)
}

pub(crate) fn set_auto_lock_at(vault: &Path, minutes: u32) -> Result<Settings, CommandError> {
    if !AUTO_LOCK_CHOICES.contains(&minutes) {
        return Err(CommandError {
            code: "invalid_setting",
            message: format!("lock after 1, 5, 15, or 60 minutes, not {minutes}"),
        });
    }
    let settings = Settings {
        auto_lock_minutes: minutes,
    };
    write(vault, &settings).map_err(|error| CommandError {
        code: "storage",
        message: format!("the settings could not be saved: {error}"),
    })?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_auto_lock_time_is_one_of_four_and_kept_beside_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        assert_eq!(read(&vault).auto_lock_minutes, 5);
        assert_eq!(set_auto_lock_at(&vault, 15).unwrap().auto_lock_minutes, 15);
        assert_eq!(read(&vault).auto_lock_minutes, 15);
        assert_eq!(
            set_auto_lock_at(&vault, 7).unwrap_err().code,
            "invalid_setting"
        );
        assert_eq!(read(&vault).auto_lock_minutes, 15);
        // What another program left there is not taken for a setting.
        std::fs::write(
            dir.path().join("settings.json"),
            br#"{"autoLockMinutes": 0}"#,
        )
        .unwrap();
        assert_eq!(read(&vault).auto_lock_minutes, 5);
        std::fs::write(dir.path().join("settings.json"), b"not json").unwrap();
        assert_eq!(read(&vault).auto_lock_minutes, 5);
    }
}
