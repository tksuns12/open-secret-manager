//! Bringing in the logins another app exported: Bitwarden's unencrypted
//! JSON, or Chrome's or Firefox's CSV.
//!
//! The owner picks the export in the system's dialog, which these commands
//! open; the file is read here and never reaches the window, which sees
//! only what the import would add and what was skipped. Nothing is written
//! until the owner confirms, and locking drops what was read.

use std::path::Path;

use osm_vault_core::{preview_import, ImportFormat, ItemKind};
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::{network, AppState, CommandError};

/// An export larger than this is no export of a person's logins; the
/// shared code refuses one past its own limit too.
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// What an import would add, as the window shows it before the owner
/// confirms. No secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub(crate) file: String,
    pub(crate) items: usize,
    pub(crate) logins: usize,
    pub(crate) notes: usize,
    pub(crate) cards: usize,
    pub(crate) identities: usize,
    /// Items with the same kind, website, and username as one the vault
    /// has: they are added as items of their own all the same.
    pub(crate) already: usize,
    /// Entries of the file that were skipped, with why.
    pub(crate) warnings: Vec<Skipped>,
}

#[derive(Debug, Serialize)]
pub struct Skipped {
    pub(crate) row: usize,
    pub(crate) message: String,
}

fn locked() -> CommandError {
    CommandError {
        code: "locked",
        message: "vault is locked".into(),
    }
}

fn format_of(name: &str) -> Result<(ImportFormat, &'static str, &'static str), CommandError> {
    match name {
        "bitwarden" => Ok((
            ImportFormat::BitwardenJson,
            "Bitwarden export (unencrypted JSON)",
            "json",
        )),
        "chrome" => Ok((ImportFormat::ChromeCsv, "Chrome passwords (CSV)", "csv")),
        "firefox" => Ok((ImportFormat::FirefoxCsv, "Firefox logins (CSV)", "csv")),
        _ => Err(CommandError {
            code: "invalid_import",
            message: "that is not a kind of export this app reads".into(),
        }),
    }
}

/// Asks for an export of `format` (`bitwarden`, `chrome`, or `firefox`),
/// reads it, and keeps what it would add for [`confirm_import`]. `None` if
/// the owner closed the dialog.
#[tauri::command]
pub async fn choose_import<R: Runtime>(
    format: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<Option<ImportSummary>, CommandError> {
    let (format, kind, extension) = format_of(&format)?;
    // The owner is not asked for a file that cannot be imported.
    if !state
        .vault
        .lock()
        .await
        .as_ref()
        .is_some_and(|vault| vault.is_unlocked())
    {
        return Err(locked());
    }
    let mut ask = app
        .dialog()
        .file()
        .set_title("Choose an export to import")
        .add_filter(kind, &[extension]);
    if let Some(window) = app.get_webview_window("main") {
        ask = ask.set_parent(&window);
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    ask.pick_file(move |path| {
        let _ = sender.send(path);
    });
    let Some(path) = receiver
        .await
        .ok()
        .flatten()
        .and_then(|path| path.into_path().ok())
    else {
        return Ok(None);
    };
    preview_file(&state, &path, format).await.map(Some)
}

/// Reads the export at `path` and keeps what it would add, replacing any
/// import not yet confirmed.
pub(crate) async fn preview_file(
    state: &AppState,
    path: &Path,
    format: ImportFormat,
) -> Result<ImportSummary, CommandError> {
    let size = std::fs::metadata(path)
        .map_err(|error| CommandError {
            code: "invalid_import",
            message: format!("the file cannot be read: {error}"),
        })?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(CommandError {
            code: "invalid_import",
            message: "the file is too large to be an export of logins".into(),
        });
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|error| CommandError {
        code: "invalid_import",
        message: format!("the file cannot be read: {error}"),
    })?);
    let preview = preview_import(format, &bytes)?;
    let existing = {
        let vault = state.vault.lock().await;
        vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?
            .list()?
    };
    let count = |kind: ItemKind| {
        preview
            .items()
            .iter()
            .filter(|item| item.kind == kind)
            .count()
    };
    let summary = ImportSummary {
        file: path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned(),
        items: preview.valid_count(),
        logins: count(ItemKind::Login),
        notes: count(ItemKind::SecureNote),
        cards: count(ItemKind::Card),
        identities: count(ItemKind::Identity),
        already: preview
            .items()
            .iter()
            .filter(|item| {
                existing.iter().any(|known| {
                    known.kind == item.kind
                        && known.url.trim() == item.url.trim()
                        && known.username.trim() == item.username.trim()
                        && (!item.url.trim().is_empty() || !item.username.trim().is_empty())
                })
            })
            .count(),
        warnings: preview
            .warnings()
            .iter()
            .map(|warning| Skipped {
                row: warning.row,
                message: warning.message.clone(),
            })
            .collect(),
    };
    *state.import.lock().await = Some(preview);
    Ok(summary)
}

/// Adds what the chosen export holds to the vault, as new items, and
/// returns how many. Online, they sync at once.
#[tauri::command]
pub async fn confirm_import<R: Runtime>(
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<usize, CommandError> {
    let added = confirm(&state).await?;
    network::schedule_sync(&app);
    Ok(added)
}

pub(crate) async fn confirm(state: &AppState) -> Result<usize, CommandError> {
    let preview = state
        .import
        .lock()
        .await
        .take()
        .ok_or_else(|| CommandError {
            code: "no_import",
            message: "choose an export first".into(),
        })?;
    let mut vault = state.vault.lock().await;
    let vault = vault
        .as_mut()
        .filter(|vault| vault.is_unlocked())
        .ok_or_else(locked)?;
    Ok(vault.confirm_import(preview)?.len())
}

/// Drops the export read for an import the owner did not confirm.
#[tauri::command]
pub async fn cancel_import(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    state.import.lock().await.take();
    Ok(())
}
