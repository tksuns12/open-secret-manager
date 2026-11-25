//! Copies of a vault that were put away on this device.
//!
//! A copy is put away, into an `archive-<time>` folder beside the vault,
//! when this device is removed from its vault, when the owner has it leave
//! a vault that was replaced, and when this device starts over as a new
//! vault. Such a copy can hold changes that never reached another device.
//! The owner can open one with the password it had, see what it holds,
//! copy an item into the vault this device has now, and delete the copy.
//!
//! An item's password and one-time-code secret never cross the bridge: a
//! copy is made between the two vaults here.

use std::path::{Path, PathBuf};

use osm_vault_core::{Item, ItemKind, Vault};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};

use crate::{network, AppState, CommandError};

/// Added to the title of a copied item when the vault already has that
/// item, so that the two can be told apart.
const COPY_SUFFIX: &str = " (archived copy)";

/// An archived copy the owner has opened with its password.
pub struct Opened {
    name: String,
    vault: Vault,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveInfo {
    /// The folder's name, which is how the other commands refer to it.
    pub(crate) name: String,
    /// When the copy was put away, in seconds since the Unix epoch.
    archived_at: u64,
    path: String,
    /// Whether the folder holds a vault file.
    pub(crate) has_vault: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedItem {
    pub(crate) id: String,
    pub(crate) title: String,
    kind: ItemKind,
    username: String,
    url: String,
    /// The archived copy holds conflicting versions of this item; the one
    /// shown is the one that copy showed.
    conflict: bool,
    /// How the item relates to the vault this device has now: `same` (the
    /// vault holds it, or a copy made from here), `differs` (the vault
    /// holds the item with other content), or `absent`. `None` when there
    /// is no unlocked vault to compare with.
    pub(crate) relation: Option<&'static str>,
    /// For `differs`: which fields differ.
    pub(crate) changed: Vec<&'static str>,
}

/// When the copy in a folder of this name was put away, if the name is one
/// this app gives an archive folder: `archive-<seconds>`, with a counter
/// after it when two were made in the same second.
pub(crate) fn archived_at(name: &str) -> Option<u64> {
    let mut parts = name.strip_prefix("archive-")?.split('-');
    let seconds = parts.next()?;
    let counter = parts.next();
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if parts.next().is_some() || !digits(seconds) || !counter.is_none_or(digits) {
        return None;
    }
    seconds.parse().ok()
}

fn directory(state: &AppState) -> &Path {
    state.path.parent().unwrap_or(Path::new("."))
}

fn vault_file(state: &AppState, folder: &Path) -> PathBuf {
    folder.join(state.path.file_name().unwrap_or_default())
}

fn no_archive() -> CommandError {
    CommandError {
        code: "no_archive",
        message: "there is no such archived copy".into(),
    }
}

/// The folder of an archived copy. `name` is only ever the name of a
/// folder this app made beside the vault, never a path, and a link in
/// that place is not followed.
fn archive_folder(state: &AppState, name: &str) -> Result<PathBuf, CommandError> {
    archived_at(name).ok_or_else(no_archive)?;
    let folder = directory(state).join(name);
    let is_folder = std::fs::symlink_metadata(&folder).is_ok_and(|found| found.is_dir());
    if is_folder {
        Ok(folder)
    } else {
        Err(no_archive())
    }
}

/// The copies put away on this device, newest first.
#[tauri::command]
pub async fn list_archives(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ArchiveInfo>, CommandError> {
    let Ok(entries) = std::fs::read_dir(directory(&state)) else {
        return Ok(Vec::new());
    };
    let mut archives: Vec<ArchiveInfo> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let archived_at = archived_at(&name)?;
            let folder = archive_folder(&state, &name).ok()?;
            Some(ArchiveInfo {
                has_vault: std::fs::symlink_metadata(vault_file(&state, &folder))
                    .is_ok_and(|meta| meta.is_file()),
                path: folder.to_string_lossy().into_owned(),
                archived_at,
                name,
            })
        })
        .collect();
    archives.sort_by(|a, b| (b.archived_at, &b.name).cmp(&(a.archived_at, &a.name)));
    Ok(archives)
}

/// Whether `current` holds what `archived` holds: every field alike, the
/// title either alike or the one a copy made from here was given.
fn same_content(archived: &Item, current: &Item) -> bool {
    crate::changed_fields(archived, current)
        .into_iter()
        .all(|field| field == "title")
        && (current.title == archived.title
            || current.title.strip_suffix(COPY_SUFFIX) == Some(archived.title.as_str()))
}

/// What the opened copy holds, each item with how it relates to the vault
/// this device has now.
fn items(opened: &Opened, current: Option<&Vault>) -> Result<Vec<ArchivedItem>, CommandError> {
    let current: Option<Vec<Item>> = match current.filter(|vault| vault.is_unlocked()) {
        Some(vault) => Some(
            vault
                .list()?
                .iter()
                .map(|summary| vault.get(&summary.id).map(|found| found.item))
                .collect::<Result<_, _>>()?,
        ),
        None => None,
    };
    let mut listed = Vec::new();
    for summary in opened.vault.list()? {
        let archived = opened.vault.get(&summary.id)?;
        let item = &archived.item;
        let (relation, changed) = match &current {
            None => (None, Vec::new()),
            Some(current) if current.iter().any(|held| same_content(item, held)) => {
                (Some("same"), Vec::new())
            }
            Some(current) => match current.iter().find(|held| held.id == item.id) {
                Some(held) => (Some("differs"), crate::changed_fields(item, held)),
                None => (Some("absent"), Vec::new()),
            },
        };
        listed.push(ArchivedItem {
            id: item.id.clone(),
            title: item.title.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
            conflict: archived.conflict,
            relation,
            changed,
        });
    }
    listed.sort_by_key(|item| item.title.to_lowercase());
    Ok(listed)
}

/// Opens an archived copy with the password it had when it was put away
/// and lists what it holds. It stays open until it is closed, another is
/// opened, or the vault locks.
#[tauri::command]
pub async fn open_archive(
    name: String,
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ArchivedItem>, CommandError> {
    let password = zeroize::Zeroizing::new(password);
    let folder = archive_folder(&state, &name)?;
    let path = vault_file(&state, &folder);
    if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
        return Err(no_archive());
    }
    let mut vault = Vault::open(&path)?;
    vault.unlock(&password)?;
    let current = state.vault.lock().await;
    let mut archive = state.archive.lock().await;
    let opened = archive.insert(Opened { name, vault });
    items(opened, current.as_ref())
}

/// Copies an item of the opened archived copy into the vault this device
/// has now, as a new item. If the vault already has that item, the copy's
/// title says where it came from. Returns the archived copy's items again,
/// with how they relate to the vault now.
#[tauri::command]
pub async fn copy_from_archive<R: Runtime>(
    id: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<Vec<ArchivedItem>, CommandError> {
    let mut current = state.vault.lock().await;
    let archive = state.archive.lock().await;
    let opened = archive.as_ref().ok_or_else(no_archive)?;
    let vault = current
        .as_mut()
        .filter(|vault| vault.is_unlocked())
        .ok_or_else(|| CommandError {
            code: "locked",
            message: "unlock the vault first".into(),
        })?;
    let source = opened.vault.get(&id)?.item;
    let held = match vault.get(&id) {
        Ok(_) => true,
        Err(osm_vault_core::Error::NotFound) => false,
        Err(error) => return Err(error.into()),
    };
    // A new item: the vault's own item of that ID, live or deleted, keeps
    // its history untouched.
    let mut copy = Item::new(if held {
        format!("{}{COPY_SUFFIX}", source.title)
    } else {
        source.title.clone()
    });
    copy.kind = source.kind;
    copy.username = source.username.clone();
    copy.password = source.password.clone();
    copy.url = source.url.clone();
    copy.notes = source.notes.clone();
    copy.totp_secret = source.totp_secret.clone();
    copy.custom_fields = source.custom_fields.clone();
    copy.tags = source.tags.clone();
    copy.favorite = source.favorite;
    copy.unknown_fields = source.unknown_fields.clone();
    vault.put(copy)?;
    network::schedule_sync(&app);
    items(opened, Some(vault))
}

#[tauri::command]
pub async fn close_archive(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    *state.archive.lock().await = None;
    Ok(())
}

/// Deletes an archived copy for good: the folder and everything in it.
#[tauri::command]
pub async fn delete_archive<R: Runtime>(
    name: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let folder = archive_folder(&state, &name)?;
    {
        // Close its files first.
        let mut archive = state.archive.lock().await;
        if archive.as_ref().is_some_and(|opened| opened.name == name) {
            *archive = None;
        }
    }
    std::fs::remove_dir_all(&folder).map_err(|error| CommandError {
        code: "storage",
        message: error.to_string(),
    })?;
    // What happened to this device's last vault no longer points anywhere.
    state.network.forget_archive(&folder);
    let _ = app.emit("devices-changed", ());
    Ok(())
}
