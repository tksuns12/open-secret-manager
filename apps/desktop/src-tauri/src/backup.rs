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
//!
//! This device notes when it last saved a backup of its vault, beside the
//! vault in `backups.json`, and since Phase 15 in the vault itself, which
//! syncs it to the vault's other devices, so that the window can remind the
//! owner once [`REMIND_AFTER_DAYS`] have passed without one from any of
//! them, or [`FIRST_REMIND_AFTER_DAYS`] for a vault none of them has ever
//! backed up.

use std::path::{Path, PathBuf};

use osm_vault_core::RecoveryKey;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder};
use zeroize::Zeroizing;

use crate::{history, network, AppState, CommandError};

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

/// Seconds since 1970 by this computer's clock.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Today's date as the calendar has it in UTC, for a file's name.
fn today() -> String {
    date_of((now() / 86_400) as i64)
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
    let saved = write(&state, &path).await?;
    // For the vault's other devices to learn of it.
    network::schedule_sync(&app);
    Ok(Some(saved))
}

/// Writes a backup to `path` and reads it back.
pub(crate) async fn write(state: &AppState, path: &Path) -> Result<Saved, CommandError> {
    let mut vault = state.vault.lock().await;
    let vault = vault
        .as_mut()
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
    // The backup stands whether or not its time is noted; a time that could
    // not be noted only brings the reminder sooner.
    let _ = note_backup(&state.path, &vault.vault_id(), now());
    let _ = vault.note_backup();
    Ok(Saved {
        path: path.to_string_lossy().into_owned(),
        items: check.items,
        revisions: check.revisions,
        held: check.held,
    })
}

/// Days without a backup after which the window reminds of one.
pub const REMIND_AFTER_DAYS: u64 = 30;
/// The same for a vault never backed up, counted from the device's first
/// look: until its first backup, the vault is on its devices alone, so the
/// owner is reminded the day after, not a month after.
pub const FIRST_REMIND_AFTER_DAYS: u64 = 1;
const DAY: u64 = 86_400;

/// When this device last saved a backup, kept beside the vault in
/// `backups.json`. Only the vault it holds now counts: once that is another
/// vault (one restored, joined, or made anew), the count starts again.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupRecord {
    /// The vault the times are for.
    vault: String,
    /// When this device began counting, for a vault it has not backed up:
    /// the first time it looked. Seconds since 1970.
    since: u64,
    /// When this device last saved a backup of the vault. Seconds since 1970.
    last_backup: Option<u64>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupAge {
    /// Whole days since the latest backup of its vault, from this device or,
    /// as the vault noted it, from another; none if there is none.
    pub(crate) days: Option<u64>,
    /// Whether to remind the owner: [`REMIND_AFTER_DAYS`] or more since that
    /// backup, or [`FIRST_REMIND_AFTER_DAYS`] since the device began counting
    /// without one.
    pub(crate) due: bool,
    /// The device that saved the latest backup, as the first eight hex
    /// digits of its ID, when it is another than this one.
    pub(crate) device: Option<String>,
}

fn record_file(vault: &Path) -> PathBuf {
    vault.with_file_name("backups.json")
}

fn read_record(vault: &Path, id: &str) -> Option<BackupRecord> {
    std::fs::read(record_file(vault))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BackupRecord>(&bytes).ok())
        .filter(|record| record.vault == id)
}

fn write_record(vault: &Path, record: &BackupRecord) -> std::io::Result<()> {
    let path = record_file(vault);
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, serde_json::to_vec_pretty(record)?)?;
    std::fs::rename(&partial, &path)
}

/// Notes that this device saved a backup of the vault `id` at `at`.
pub(crate) fn note_backup(vault: &Path, id: &[u8], at: u64) -> std::io::Result<()> {
    let id = network::hex(id);
    let since = read_record(vault, &id).map_or(at, |record| record.since);
    write_record(
        vault,
        &BackupRecord {
            vault: id,
            since,
            last_backup: Some(at),
        },
    )
}

/// How long the vault `id` has gone without a backup from this device, at
/// `at`. A device without recovery cannot save one, so it is not reminded.
#[cfg(test)]
pub(crate) fn backup_age_at(vault: &Path, id: &[u8], recovery: bool, at: u64) -> BackupAge {
    backup_age_with(vault, id, recovery, None, at)
}

/// The same, counting also the latest backup the vault has noted, `noted`:
/// when, and which device saved it if another than this one.
pub(crate) fn backup_age_with(
    vault: &Path,
    id: &[u8],
    recovery: bool,
    noted: Option<(u64, Option<String>)>,
    at: u64,
) -> BackupAge {
    let id = network::hex(id);
    let record = read_record(vault, &id).unwrap_or_else(|| {
        let record = BackupRecord {
            vault: id,
            since: at,
            last_backup: None,
        };
        // Not noted, the count starts again at the next look: the reminder
        // comes later, never sooner.
        let _ = write_record(vault, &record);
        record
    });
    // This device's own, or the vault's, whichever is later.
    let last = match (record.last_backup, noted) {
        (Some(own), Some((other, _))) if own >= other => Some((own, None)),
        (_, Some(noted)) => Some(noted),
        (own, None) => own.map(|own| (own, None)),
    };
    let days = last
        .as_ref()
        .map(|(last, _)| at.saturating_sub(*last) / DAY);
    let counted = at.saturating_sub(last.as_ref().map_or(record.since, |(last, _)| *last)) / DAY;
    let after = if last.is_some() {
        REMIND_AFTER_DAYS
    } else {
        FIRST_REMIND_AFTER_DAYS
    };
    BackupAge {
        days,
        due: recovery && counted >= after,
        device: last.and_then(|(_, device)| device),
    }
}

/// How long this device's vault has gone without a backup from it.
#[tauri::command]
pub async fn backup_age(state: tauri::State<'_, AppState>) -> Result<BackupAge, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault
        .as_ref()
        .filter(|vault| vault.is_unlocked())
        .ok_or_else(locked)?;
    let this_device = vault.device_id();
    let noted = vault.last_backup()?.map(|(at, by)| {
        (
            at,
            (Some(by) != this_device).then(|| history::short_device(&by)),
        )
    });
    Ok(backup_age_with(
        &state.path,
        &vault.vault_id(),
        vault.recovery_enabled(),
        noted,
        now(),
    ))
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
    crate::check_new_password(&new_password)?;
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
    use super::*;

    #[test]
    fn a_backup_is_due_thirty_days_after_the_last_one_or_a_day_after_counting_began() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        let start = 1_800_000_000;
        // Whole days since the last backup, and whether one is due, at `at`.
        let age_of = |id: [u8; 32], recovery: bool, at: u64| {
            let age = backup_age_at(&vault, &id, recovery, at);
            (age.days, age.due)
        };
        let age = |at| age_of([1; 32], true, at);
        // Never backed up: counting begins at the first look, and reminds
        // a day later.
        assert_eq!(age(start), (None, false));
        assert_eq!(age(start + DAY - 1), (None, false));
        assert_eq!(age(start + DAY), (None, true));
        assert_eq!(age(start + 30 * DAY), (None, true));
        // A backup starts the count again, by whole days.
        note_backup(&vault, &[1; 32], start + 31 * DAY).unwrap();
        assert_eq!(age(start + 31 * DAY + 3_600), (Some(0), false));
        assert_eq!(age(start + 61 * DAY - 1), (Some(29), false));
        assert_eq!(age(start + 61 * DAY), (Some(30), true));
        // A device without recovery cannot back up, so is not reminded.
        assert_eq!(age_of([1; 32], false, start + 90 * DAY), (Some(59), false));
        // A clock set back counts no days.
        assert_eq!(age(start), (Some(0), false));
        // Another vault in its place starts again; its first look is noted.
        assert_eq!(age_of([2; 32], true, start + 100 * DAY), (None, false));
        assert_eq!(age_of([2; 32], true, start + 101 * DAY), (None, true));
        // What another program left there is not taken for a record.
        std::fs::write(dir.path().join("backups.json"), b"not json").unwrap();
        assert_eq!(age_of([2; 32], true, start + 200 * DAY), (None, false));
    }

    #[test]
    fn a_backup_another_device_saved_counts_as_this_ones_would() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        let start = 1_800_000_000;
        let other = Some("9f8e7d6c".to_owned());
        let age = |noted: Option<(u64, Option<String>)>, at: u64| {
            let age = backup_age_with(&vault, &[1; 32], true, noted, at);
            (age.days, age.due, age.device)
        };
        // Counting began here at the first look; another device's later
        // backup puts the reminder off, and says whose it was.
        assert_eq!(age(None, start), (None, false, None));
        assert_eq!(age(None, start + DAY), (None, true, None));
        assert_eq!(age(None, start + 30 * DAY), (None, true, None));
        let noted = Some((start + 29 * DAY, other.clone()));
        assert_eq!(
            age(noted.clone(), start + 30 * DAY),
            (Some(1), false, other.clone())
        );
        // A backup saved here since is the latest, and is this device's.
        note_backup(&vault, &[1; 32], start + 40 * DAY).unwrap();
        assert_eq!(age(noted.clone(), start + 41 * DAY), (Some(1), false, None));
        // The vault's note of this device's own backup names no other.
        assert_eq!(
            age(Some((start + 50 * DAY, None)), start + 80 * DAY),
            (Some(30), true, None)
        );
        // One noted later on another device is the latest.
        assert_eq!(
            age(Some((start + 60 * DAY, other.clone())), start + 80 * DAY),
            (Some(20), false, other)
        );
    }

    #[test]
    fn a_days_count_is_written_as_the_calendar_has_it() {
        for (days, date) in [
            (0, "1970-01-01"),
            (11_016, "2000-02-29"),
            (20_088, "2024-12-31"),
            (20_729, "2026-10-03"),
            (47_541, "2100-03-01"),
        ] {
            assert_eq!(date_of(days), date);
        }
    }
}
