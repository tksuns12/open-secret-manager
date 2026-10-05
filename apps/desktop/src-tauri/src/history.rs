//! An item's history and the items deleted, and bringing a version back:
//! an earlier version of an item, or an item as it was before it was
//! deleted. A restore is a new version, which syncs like any edit; the
//! version it replaces stays in the history.
//!
//! The window is told what each version held that it may show (title,
//! username, website) and which fields it changed, never a secret.

use osm_vault_core::{HistoryVersion, Item, ItemKind, ItemSummary};
use serde::Serialize;
use tauri::{AppHandle, Runtime};

use crate::{network, AppState, CommandError};

/// One version of an item, as the history shows it. No secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub(crate) revision: String,
    /// It deleted the item.
    pub(crate) deleted: bool,
    /// It is one of the item's current versions.
    pub(crate) current: bool,
    /// It followed no version: the item was made.
    pub(crate) first: bool,
    /// It followed several versions: it settled a conflict.
    pub(crate) merged: bool,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) url: String,
    /// What it changed from the version it followed, by field name.
    pub(crate) changed: Vec<&'static str>,
    /// Short hex prefix of the device that made it.
    pub(crate) device: String,
    pub(crate) this_device: bool,
}

/// An item deleted on every device that has it, as it was before. No secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedEntry {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) kind: ItemKind,
    pub(crate) username: String,
    pub(crate) url: String,
    /// The version before the deletion, which a restore brings back.
    pub(crate) last: String,
    /// The deletions, which a restore follows.
    pub(crate) heads: Vec<String>,
    /// Short hex prefix of the device that deleted it.
    pub(crate) device: String,
    pub(crate) this_device: bool,
}

fn locked() -> CommandError {
    CommandError {
        code: "locked",
        message: "vault is locked".into(),
    }
}

pub(crate) fn short_device(id: &[u8; 16]) -> String {
    id[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The fields `item` changed from `before`, by the names the window uses.
fn changes(before: &Item, item: &Item) -> Vec<&'static str> {
    [
        (before.title != item.title, "title"),
        (before.kind != item.kind, "type"),
        (before.username != item.username, "username"),
        (before.password != item.password, "password"),
        (before.url != item.url, "website"),
        (before.totp_secret != item.totp_secret, "one-time code"),
        (before.notes != item.notes, "notes"),
        (before.custom_fields != item.custom_fields, "other fields"),
        (before.tags != item.tags, "tags"),
        (before.favorite != item.favorite, "favorite"),
    ]
    .into_iter()
    .filter_map(|(changed, name)| changed.then_some(name))
    .collect()
}

pub(crate) fn entries(
    history: &[HistoryVersion],
    this_device: Option<[u8; 16]>,
) -> Vec<HistoryEntry> {
    history
        .iter()
        .map(|version| {
            // What it followed: the nearest version that held the item.
            let before = version.parents.iter().find_map(|parent| {
                history
                    .iter()
                    .find(|other| &other.revision == parent)
                    .and_then(|other| other.item.as_ref())
            });
            let changed = match (before, version.item.as_ref()) {
                (Some(before), Some(item)) => changes(before, item),
                _ => Vec::new(),
            };
            let shown = version.item.as_ref().or(before);
            HistoryEntry {
                revision: version.revision.clone(),
                deleted: version.item.is_none(),
                current: version.current,
                first: version.parents.is_empty(),
                merged: version.parents.len() > 1,
                title: shown.map(|item| item.title.clone()).unwrap_or_default(),
                username: shown.map(|item| item.username.clone()).unwrap_or_default(),
                url: shown.map(|item| item.url.clone()).unwrap_or_default(),
                changed,
                device: short_device(&version.author_device_id),
                this_device: Some(version.author_device_id) == this_device,
            }
        })
        .collect()
}

/// Every version of an item, newest first.
#[tauri::command]
pub async fn item_history(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<HistoryEntry>, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(locked)?;
    let history = vault.history(&id)?;
    Ok(entries(&history, vault.device_id()))
}

/// The items deleted, most recently first.
#[tauri::command]
pub async fn deleted_entries(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<DeletedEntry>, CommandError> {
    let vault = state.vault.lock().await;
    let vault = vault.as_ref().ok_or_else(locked)?;
    let this_device = vault.device_id();
    Ok(vault
        .deleted_items()?
        .into_iter()
        .filter_map(|deleted| {
            let item = deleted.last.item.as_ref()?;
            Some(DeletedEntry {
                id: deleted.item_id.clone(),
                title: item.title.clone(),
                kind: item.kind,
                username: item.username.clone(),
                url: item.url.clone(),
                last: deleted.last.revision.clone(),
                device: short_device(&deleted.deleted_by),
                this_device: Some(deleted.deleted_by) == this_device,
                heads: deleted.heads,
            })
        })
        .collect())
}

/// Brings back what the version `revision` of an item held, following the
/// current versions `heads` the window was shown.
#[tauri::command]
pub async fn restore_entry<R: Runtime>(
    id: String,
    revision: String,
    heads: Vec<String>,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<ItemSummary, CommandError> {
    let summary = {
        let mut vault = state.vault.lock().await;
        let vault = vault.as_mut().ok_or_else(locked)?;
        vault.restore(&id, &revision, &heads)?;
        vault.get(&id)?.into()
    };
    network::schedule_sync(&app);
    Ok(summary)
}
