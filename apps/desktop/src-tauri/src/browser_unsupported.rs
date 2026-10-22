//! Stands in for the browser session on a system without Unix sockets,
//! which is how the native messaging host reaches the app: no request ever
//! arrives, and no browser can be connected.

use std::path::Path;

use serde::Serialize;
use tauri::{AppHandle, Runtime};

use crate::{AppState, CommandError};

pub struct Browser;

impl Browser {
    pub fn open(_vault_path: &Path) -> Self {
        Self
    }
}

pub fn start<R: Runtime>(_app: &AppHandle<R>) {}

fn unsupported() -> CommandError {
    CommandError {
        code: "unsupported",
        message: "filling into a browser is not available on this system".into(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    supported: bool,
    listening: bool,
    problem: Option<String>,
    host: Option<String>,
    temporary_place: bool,
    browsers: Vec<()>,
}

fn status() -> BrowserStatus {
    BrowserStatus {
        supported: false,
        listening: false,
        problem: Some(unsupported().message),
        host: None,
        temporary_place: false,
        browsers: Vec::new(),
    }
}

#[tauri::command]
pub async fn fill_request(_state: tauri::State<'_, AppState>) -> Result<Option<()>, CommandError> {
    Ok(None)
}

#[tauri::command]
pub async fn approve_fill(
    _request_id: String,
    _item_id: String,
    _session: String,
) -> Result<(), CommandError> {
    Err(unsupported())
}

#[tauri::command]
pub async fn approve_card(
    _request_id: String,
    _item_id: String,
    _session: String,
) -> Result<(), CommandError> {
    Err(unsupported())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn approve_passkey(
    _request_id: String,
    _session: String,
    _into: Option<String>,
    _item_id: Option<String>,
    _credential_id: Option<String>,
    _password: Option<String>,
    _owner_check: bool,
) -> Result<(), CommandError> {
    Err(unsupported())
}

#[tauri::command]
pub async fn use_browser_passkey(_request_id: String) -> Result<(), CommandError> {
    Err(unsupported())
}

#[tauri::command]
pub async fn deny_fill(_request_id: String) -> Result<(), CommandError> {
    Err(unsupported())
}

#[tauri::command]
pub async fn browser_status() -> Result<BrowserStatus, CommandError> {
    Ok(status())
}

#[tauri::command]
pub async fn connect_browser(_browser: String) -> Result<BrowserStatus, CommandError> {
    Err(unsupported())
}

#[tauri::command]
pub async fn disconnect_browser(_browser: String) -> Result<BrowserStatus, CommandError> {
    Err(unsupported())
}
