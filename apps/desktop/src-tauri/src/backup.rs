//! Backups the owner saves and restores, and a forgotten password.
//!
//! A backup is one file holding every item with its history, written by
//! this device and opened by the vault's recovery key, not by a password.
//! It is checked by reading it back as soon as it is written. Restoring one
//! makes a new vault on a device without one (see [`network::restore`]).
//! The recovery key also replaces a forgotten password.
//!
//! The window never names a file: the owner picks one in the system's
//! dialog, which these commands open, and the path stays here.

use std::path::{Path, PathBuf};

use osm_vault_core::RecoveryKey;
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder};
use zeroize::Zeroizing;

use crate::{network, AppState, CommandError};

/// What a backup file is called, for the dialogs.
const KIND: &str = "Open Secret Manager backup";
const EXTENSION: &str = "osmbackup";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    pub(crate) path: String,
    /// Items in the backup, deleted ones included.
    pub(crate) items: usize,
    /// Versions of those items, kept as history.
    pub(crate) revisions: usize,
    /// Changes held for review, which a backup keeps too.
    pub(crate) held: usize,
}

fn locked() -> CommandError {
    CommandError {
        code: "locked",
        message: "vault is locked".into(),
    }
}

/// Today's date as the calendar has it in UTC, for a file's name.
fn today() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / 86_400);
    date_of(days as i64)
}

/// The date `days` days after 1970-01-01, by Howard Hinnant's
/// days-to-civil conversion.
fn date_of(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// A file dialog over the app's window.
fn dialog<R: Runtime>(app: &AppHandle<R>) -> FileDialogBuilder<R> {
    let mut dialog = app.dialog().file().add_filter(KIND, &[EXTENSION]);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog
}

/// Waits for the owner's choice in a dialog without holding a thread.
async fn chosen(
    show: impl FnOnce(Box<dyn FnOnce(Option<tauri_plugin_dialog::FilePath>) + Send>),
) -> Option<PathBuf> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    show(Box::new(move |path| {
        let _ = sender.send(path);
    }));
    receiver.await.ok().flatten()?.into_path().ok()
}

/// Asks where to save a backup and saves it there. `None` if the owner
/// closed the dialog.
#[tauri::command]
pub async fn save_backup<R: Runtime>(
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<Option<Saved>, CommandError> {
    // The owner is not asked where to save what cannot be written.
    {
        let vault = state.vault.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        if !vault.recovery_enabled() {
            return Err(osm_vault_core::Error::RecoveryNotEnabled.into());
        }
    }
    let mut ask = dialog(&app)
        .set_title("Save a backup")
        .set_file_name(format!("{KIND} {}.{EXTENSION}", today()));
    if let Some(documents) = dirs::document_dir() {
        ask = ask.set_directory(documents);
    }
    let Some(path) = chosen(|answer| ask.save_file(answer)).await else {
        return Ok(None);
    };
    write(&state, &path).await.map(Some)
}

/// Writes a backup to `path` and reads it back.
pub(crate) async fn write(state: &AppState, path: &Path) -> Result<Saved, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault
        .as_ref()
        .filter(|vault| vault.is_unlocked())
        .ok_or_else(locked)?;
    vault.export_backup(path).map_err(|error| match error {
        osm_vault_core::Error::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
            CommandError {
                code: "exists",
                message: "a file of that name is already there, and an older backup is never replaced: choose another name".into(),
            }
        }
        error => error.into(),
    })?;
    let check = vault.check_backup(path)?;
    Ok(Saved {
        path: path.to_string_lossy().into_owned(),
        items: check.items,
        revisions: check.revisions,
        held: check.held,
    })
}

/// Asks for a backup to restore and keeps the owner's choice for
/// [`restore_backup`]. Returns the file's name, or `None` if the owner
/// closed the dialog.
#[tauri::command]
pub async fn choose_backup<R: Runtime>(
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<Option<String>, CommandError> {
    let ask = dialog(&app).set_title("Choose a backup to restore");
    let path = chosen(|answer| ask.pick_file(answer)).await;
    let name = path.as_ref().map(|path| {
        path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned()
    });
    *state
        .chosen_backup
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = path;
    Ok(name)
}

/// Restores the backup the owner chose as a new vault on this device.
#[tauri::command]
pub async fn restore_backup<R: Runtime>(
    recovery_key: String,
    password: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<network::Restored, CommandError> {
    let recovery_key = Zeroizing::new(recovery_key);
    let password = Zeroizing::new(password);
    let backup = state
        .chosen_backup
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .ok_or_else(|| CommandError {
            code: "no_backup",
            message: "choose a backup first".into(),
        })?;
    let recovery = RecoveryKey::parse(recovery_key.trim())?;
    network::restore(&app, &backup, &recovery, &password).await
}

/// For a forgotten password: the recovery key unlocks the vault, and the
/// new password replaces the old one on this device.
#[tauri::command]
pub async fn reset_password<R: Runtime>(
    recovery_key: String,
    new_password: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let recovery_key = Zeroizing::new(recovery_key);
    let new_password = Zeroizing::new(new_password);
    let recovery = RecoveryKey::parse(recovery_key.trim())?;
    {
        let mut vault = state.vault.lock().await;
        let vault = vault.as_mut().ok_or_else(|| CommandError {
            code: "vault_missing",
            message: "vault has not been configured".into(),
        })?;
        vault.reset_password(&recovery, &new_password)?;
    }
    // As after any unlock: membership first, then what arrived while locked.
    network::after_unlock(&app).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_days_count_is_written_as_the_calendar_has_it() {
        for (days, date) in [
            (0, "1970-01-01"),
            (11_016, "2000-02-29"),
            (20_088, "2024-12-31"),
            (20_729, "2026-10-03"),
            (47_541, "2100-03-01"),
        ] {
            assert_eq!(super::date_of(days), date);
        }
    }
}
