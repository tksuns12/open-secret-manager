//! The app's end of filling a login, or a card, into a browser page.
//!
//! While the app is open it listens on a socket in its data folder, which
//! the native messaging host brings requests to. A request waits here for
//! the owner: the window comes forward and shows the page's origin and the
//! logins stored for exactly that origin, or, for a card form, the
//! documents to be filled and every card, and the owner picks one or turns
//! the request down. A login's password and a card's number never cross
//! the bridge to the window; they go from the vault to the socket here.
//!
//! A page's request for a passkey (Phase 18, stop 6) waits here too, but a
//! fill the owner starts takes its place, and a sign-in the unlocked vault
//! holds no passkey for is left to the browser before the window comes
//! forward. A passkey's key never crosses the bridge either: the window
//! learns the site, the account, and which login holds it.
//!
//! This module also tells each browser where the host is, by writing the
//! manifest the browser looks for, and takes that manifest away again.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

use osm_browser_link::{
    endpoint, CardField, Ceremony, Origin, CHROMIUM_EXTENSION_IDS, FIREFOX_EXTENSION_ID, HOST_NAME,
};
use osm_vault_browser::{bind, serve, Config, Desk, Refused};
use osm_vault_core::{passkey::UserVerification, ItemKind, Vault};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use zeroize::Zeroizing;

use crate::{AppState, CommandError};

/// The host's file name, beside the app's own program.
#[cfg(unix)]
const HOST_PROGRAM: &str = "osm-native-host";
#[cfg(windows)]
const HOST_PROGRAM: &str = "osm-native-host.exe";

/// A browser this app knows how to connect.
struct Known {
    id: &'static str,
    name: &'static str,
    firefox: bool,
    /// The browser's own folders, relative to the home folder: it is there
    /// if it has been used on this account, and one of them is.
    profiles: &'static [&'static str],
    /// Where the browser looks for host manifests, relative to the home
    /// folder. On Windows: the registry key, under the current user's, whose
    /// value is the manifest's file.
    hosts: &'static str,
}

#[cfg(target_os = "macos")]
const BROWSERS: [Known; 5] = [
    Known {
        id: "chrome",
        name: "Google Chrome",
        firefox: false,
        profiles: &["Library/Application Support/Google/Chrome"],
        hosts: "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    },
    Known {
        id: "chromium",
        name: "Chromium",
        firefox: false,
        profiles: &["Library/Application Support/Chromium"],
        hosts: "Library/Application Support/Chromium/NativeMessagingHosts",
    },
    Known {
        id: "brave",
        name: "Brave",
        firefox: false,
        profiles: &["Library/Application Support/BraveSoftware/Brave-Browser"],
        hosts: "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    },
    Known {
        id: "edge",
        name: "Microsoft Edge",
        firefox: false,
        profiles: &["Library/Application Support/Microsoft Edge"],
        hosts: "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    },
    Known {
        id: "firefox",
        name: "Firefox",
        firefox: true,
        profiles: &["Library/Application Support/Firefox"],
        hosts: "Library/Application Support/Mozilla/NativeMessagingHosts",
    },
];

#[cfg(all(unix, not(target_os = "macos")))]
const BROWSERS: [Known; 5] = [
    Known {
        id: "chrome",
        name: "Google Chrome",
        firefox: false,
        profiles: &[".config/google-chrome"],
        hosts: ".config/google-chrome/NativeMessagingHosts",
    },
    Known {
        id: "chromium",
        name: "Chromium",
        firefox: false,
        profiles: &[".config/chromium"],
        hosts: ".config/chromium/NativeMessagingHosts",
    },
    Known {
        id: "brave",
        name: "Brave",
        firefox: false,
        profiles: &[".config/BraveSoftware/Brave-Browser"],
        hosts: ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    },
    Known {
        id: "edge",
        name: "Microsoft Edge",
        firefox: false,
        profiles: &[".config/microsoft-edge"],
        hosts: ".config/microsoft-edge/NativeMessagingHosts",
    },
    Known {
        id: "firefox",
        name: "Firefox",
        firefox: true,
        // A new Firefox profile goes in the XDG folder (seen with Firefox
        // 157), and an earlier one stays where it was; Firefox still looks
        // for host manifests in ~/.mozilla only (tried with 157).
        profiles: &[".mozilla/firefox", ".config/mozilla/firefox"],
        hosts: ".mozilla/native-messaging-hosts",
    },
];

#[cfg(windows)]
const BROWSERS: [Known; 5] = [
    Known {
        id: "chrome",
        name: "Google Chrome",
        firefox: false,
        profiles: &["AppData/Local/Google/Chrome/User Data"],
        hosts: r"Software\Google\Chrome\NativeMessagingHosts",
    },
    Known {
        id: "chromium",
        name: "Chromium",
        firefox: false,
        profiles: &["AppData/Local/Chromium/User Data"],
        hosts: r"Software\Chromium\NativeMessagingHosts",
    },
    Known {
        id: "brave",
        name: "Brave",
        firefox: false,
        profiles: &["AppData/Local/BraveSoftware/Brave-Browser/User Data"],
        hosts: r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    },
    Known {
        id: "edge",
        name: "Microsoft Edge",
        firefox: false,
        profiles: &["AppData/Local/Microsoft/Edge/User Data"],
        hosts: r"Software\Microsoft\Edge\NativeMessagingHosts",
    },
    Known {
        id: "firefox",
        name: "Firefox",
        firefox: true,
        profiles: &["AppData/Roaming/Mozilla/Firefox"],
        hosts: r"Software\Mozilla\NativeMessagingHosts",
    },
];

impl Known {
    /// Whether the browser has been used on this account.
    fn used(&self, home: &Path) -> bool {
        self.profiles
            .iter()
            .any(|profile| home.join(profile).is_dir())
    }

    /// The manifest's file: in the folder the browser looks in, or on
    /// Windows, where the registry is told to look, in the app's own folder.
    #[cfg(unix)]
    fn manifest_path(&self, home: &Path) -> PathBuf {
        home.join(self.hosts).join(format!("{HOST_NAME}.json"))
    }

    #[cfg(windows)]
    fn manifest_path(&self, _home: &Path) -> PathBuf {
        self.manifest_folder()
            .join(format!("{HOST_NAME}-{}.json", self.id))
    }

    /// Where this account's manifests for Windows' browsers are kept.
    #[cfg(windows)]
    fn manifest_folder(&self) -> PathBuf {
        endpoint::socket_path()
            .and_then(|file| file.parent().map(|folder| folder.join("native-messaging")))
            .unwrap_or_default()
    }

    /// The manifest the browser would read, if it is told of one.
    #[cfg(unix)]
    fn found(&self, home: &Path) -> Option<PathBuf> {
        Some(self.manifest_path(home))
    }

    #[cfg(windows)]
    fn found(&self, _home: &Path) -> Option<PathBuf> {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};

        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(format!(r"{}\{HOST_NAME}", self.hosts))
            .ok()?;
        key.get_value::<String, _>("").ok().map(PathBuf::from)
    }

    /// Tells the browser where the manifest is: writes it, and on Windows
    /// registers it.
    fn connect(&self, home: &Path, manifest: &[u8]) -> std::io::Result<()> {
        let path = self.manifest_path(home);
        let folder = path.parent().unwrap_or(home);
        std::fs::create_dir_all(folder)?;
        // Written beside with a random `create_new` file and moved into place,
        // so a browser never reads half of it and a pre-planted symlink is
        // never followed.
        crate::atomic_write(&path, manifest)?;
        #[cfg(windows)]
        {
            use winreg::{enums::HKEY_CURRENT_USER, RegKey};

            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\{HOST_NAME}", self.hosts))?;
            key.set_value("", &path.to_string_lossy().into_owned())?;
        }
        Ok(())
    }

    /// Takes the browser's way to the manifest away.
    fn disconnect(&self, home: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            use winreg::{enums::HKEY_CURRENT_USER, RegKey};

            match RegKey::predef(HKEY_CURRENT_USER)
                .delete_subkey(format!(r"{}\{HOST_NAME}", self.hosts))
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        match std::fs::remove_file(self.manifest_path(home)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// The manifest that lets this browser's allowed extensions start the
    /// host: in Firefox the one, in a Chromium browser the copy loaded
    /// unpacked and the Chrome Web Store's.
    fn manifest(&self, host: &Path) -> serde_json::Value {
        let mut manifest = serde_json::json!({
            "name": HOST_NAME,
            "description": "Open Secret Manager native messaging host",
            "path": host,
            "type": "stdio",
        });
        if self.firefox {
            manifest["allowed_extensions"] = serde_json::json!([FIREFOX_EXTENSION_ID]);
        } else {
            manifest["allowed_origins"] = serde_json::json!(CHROMIUM_EXTENSION_IDS
                .iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect::<Vec<_>>());
        }
        manifest
    }
}

/// The app's browser session.
pub struct Browser {
    desk: Arc<Desk>,
    socket: PathBuf,
    /// Why the socket is not served, if it is not.
    problem: StdMutex<Option<String>>,
    /// The account's home folder, under which browsers keep their own.
    home: Option<PathBuf>,
    /// The host program, if it was found.
    host: Option<PathBuf>,
    /// The request this window was brought forward for.
    raised: StdMutex<Option<String>>,
}

impl Browser {
    pub fn open(vault_path: &Path) -> Self {
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut browser = Self::with(vault_path, dirs::home_dir(), find_host());
        // On Windows the pipe link lives in LocalAppData (`endpoint::socket_path`)
        // so the machine-local secret never syncs via Roaming Profiles.
        #[cfg(windows)]
        if let Some(socket) = endpoint::socket_path() {
            browser.socket = socket;
        }
        browser
    }

    /// A session whose browsers live under `home` and whose host program is
    /// `host`.
    pub(crate) fn with(vault_path: &Path, home: Option<PathBuf>, host: Option<PathBuf>) -> Self {
        let folder = vault_path.parent().unwrap_or(Path::new("."));
        Self {
            desk: Desk::new(Config::default()),
            socket: endpoint::socket_in(folder),
            problem: StdMutex::new(Some("the app has not started listening".into())),
            home,
            host,
            raised: StdMutex::new(None),
        }
    }

    fn known(&self, id: &str) -> Result<(&'static Known, &Path), CommandError> {
        let unknown = || CommandError {
            code: "no_browser",
            message: "that browser was not found on this device".into(),
        };
        let home = self.home.as_deref().ok_or_else(unknown)?;
        let known = BROWSERS
            .iter()
            .find(|known| known.id == id && known.used(home))
            .ok_or_else(unknown)?;
        Ok((known, home))
    }

    fn status(&self) -> BrowserStatus {
        let problem = lock(&self.problem).clone();
        let browsers = self
            .home
            .iter()
            .flat_map(|home| {
                BROWSERS
                    .iter()
                    .filter(move |known| known.used(home))
                    .map(move |known| self.browser(known, home))
            })
            .collect();
        BrowserStatus {
            supported: true,
            listening: problem.is_none(),
            problem,
            host: self
                .host
                .as_ref()
                .map(|host| host.to_string_lossy().into_owned()),
            temporary_place: self.host.as_deref().is_some_and(is_passing),
            browsers,
        }
    }

    fn browser(&self, known: &Known, home: &Path) -> BrowserInfo {
        // Where the browser looks, if it knows. On Windows a manifest that
        // no registry value points to is one the browser cannot find.
        let registered = known.found(home);
        let path = registered
            .clone()
            .unwrap_or_else(|| known.manifest_path(home));
        let found = registered
            .and_then(|path| std::fs::read(path).ok())
            .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default());
        let wanted = self.host.as_ref().map(|host| known.manifest(host));
        let (state, points_to) = match found {
            None => ("not_connected", None),
            Some(found) if Some(&found) == wanted.as_ref() => ("connected", None),
            // Something else is registered under the host's name: an
            // earlier place of this app, or not this app at all.
            Some(found) => ("other", found["path"].as_str().map(str::to_owned)),
        };
        BrowserInfo {
            id: known.id,
            name: known.name,
            state,
            manifest: path.to_string_lossy().into_owned(),
            points_to,
        }
    }
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The host program beside `program`, which is where a packaged app has it.
pub(crate) fn host_beside(program: &Path) -> Option<PathBuf> {
    let beside = program.parent()?.join(HOST_PROGRAM);
    beside.is_file().then_some(beside)
}

/// Whether `host` is in a place that is gone when the app quits, so that a
/// browser pointed at it would find nothing there later. macOS runs an app
/// that was downloaded and not moved since from a copy in a folder of its
/// own making, and an AppImage runs from a folder mounted for the one run.
pub(crate) fn is_passing(host: &Path) -> bool {
    host.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        part == "AppTranslocation" || part.starts_with(".mount_")
    })
}

/// The host program: beside the app's own, where a packaged app has it,
/// and for a development build where the repository's workspace builds it.
fn find_host() -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|program| host_beside(&program));
    if beside.is_some() {
        return beside;
    }
    #[cfg(debug_assertions)]
    for profile in ["debug", "release"] {
        let built = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target")
            .join(profile)
            .join(HOST_PROGRAM);
        if let Ok(built) = built.canonicalize() {
            return Some(built);
        }
    }
    None
}

/// Starts listening for the host and telling the window about requests.
pub fn start<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let browser = &state.browser;
    match bind(&browser.socket) {
        Ok(bound) => {
            *lock(&browser.problem) = None;
            let desk = browser.desk.clone();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let stopped = serve(bound, desk).await;
                let problem = match stopped {
                    Ok(()) => "the app stopped listening".to_owned(),
                    Err(error) => error.to_string(),
                };
                *lock(&app.state::<AppState>().browser.problem) = Some(problem);
            });
        }
        Err(error) => {
            *lock(&browser.problem) = Some(match error.kind() {
                std::io::ErrorKind::AddrInUse => {
                    "another copy of this app is already listening".into()
                }
                _ => error.to_string(),
            });
        }
    }

    // A page's sign-in the unlocked vault holds no passkey for is the
    // browser's own to answer. A vault that is busy, or locked, cannot say.
    let vault_of = app.clone();
    browser
        .desk
        .answer_sign_ins_with(Box::new(move |rp_id, allowed| {
            let state = vault_of.state::<AppState>();
            let vault = state.vault.try_lock().ok()?;
            let vault = vault.as_ref().filter(|vault| vault.is_unlocked())?;
            vault
                .passkeys_for(rp_id, allowed)
                .ok()
                .map(|found| !found.is_empty())
        }));

    let mut changes = browser.desk.changes();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut shown: Option<String> = None;
        loop {
            look(&app, &mut shown);
            let _ = app.emit("fill-request", ());
            if changes.changed().await.is_err() {
                break;
            }
        }
    });
}

/// Brings the window forward when a request arrives that was not `shown`
/// yet.
fn look<R: Runtime>(app: &AppHandle<R>, shown: &mut Option<String>) {
    let state = app.state::<AppState>();
    let asked = state
        .browser
        .desk
        .choices(None)
        .ok()
        .flatten()
        .map(|choices| choices.request_id);
    if asked == *shown {
        return;
    }
    match &asked {
        // A new request: the owner asked for it in the browser and decides
        // it here.
        Some(request) => {
            let was_behind = come_forward(app);
            *lock(&state.browser.raised) = was_behind.then(|| request.clone());
        }
        None => stop_asking_for_attention(app),
    }
    *shown = asked;
}

/// Brings the window in front of the browser. Says whether it was behind.
///
/// The system decides whether an app in the background may take the front.
/// When it does not allow it, asking for attention is what is left: the
/// app's icon signals until the owner comes to it or the request ends.
fn come_forward<R: Runtime>(app: &AppHandle<R>) -> bool {
    let Some(window) = app.get_webview_window("main") else {
        return false;
    };
    let was_behind = !window.is_focused().unwrap_or(false);
    #[cfg(target_os = "macos")]
    let _ = app.show();
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    if was_behind {
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Critical));
    }
    was_behind
}

fn stop_asking_for_attention<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.request_user_attention(None);
    }
}

/// After the owner decided a request this window came forward for, the
/// window steps back so that the browser is in front again.
fn step_back<R: Runtime>(app: &AppHandle<R>, request_id: &str) {
    let state = app.state::<AppState>();
    let mut raised = lock(&state.browser.raised);
    if raised.as_deref() != Some(request_id) {
        return;
    }
    *raised = None;
    #[cfg(target_os = "macos")]
    let _ = app.hide();
    #[cfg(not(target_os = "macos"))]
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.minimize();
    }
}

/// A login the owner may choose. Its password is not here.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillLogin {
    pub(crate) id: String,
    pub(crate) title: String,
    username: String,
    url: String,
    /// The item has conflicting versions; the one the app shows is filled.
    conflict: bool,
}

/// A login that is not offered although its address names the same host,
/// with what would have to change.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotOffered {
    pub(crate) title: String,
    url: String,
    /// `no_scheme` (the address lacks `https://`) or `not_https`.
    pub(crate) reason: &'static str,
}

/// A card the owner may choose. Its number is not here, but for the last
/// four digits.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillCard {
    pub(crate) id: String,
    title: String,
    brand: Option<String>,
    ending: Option<String>,
}

/// A document a card's request would fill, and what of the card goes there.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardDocument {
    origin: String,
    /// The page itself, not a frame in it.
    page: bool,
    fields: Vec<CardField>,
}

/// What a card's request asks.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardAsked {
    documents: Vec<CardDocument>,
    pub(crate) cards: Vec<FillCard>,
}

/// A passkey the owner may sign in with, and the login it is on. Its key is
/// not here.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillPasskey {
    pub(crate) item_id: String,
    title: String,
    pub(crate) credential_id: String,
    user_name: String,
    user_display_name: String,
}

/// What a page's request for a passkey asks.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAsked {
    /// `create` for a new passkey, `get` to sign in.
    ceremony: Ceremony,
    rp_id: String,
    /// For a new passkey: the site's name for itself, as it gave it, and the
    /// account.
    rp_name: String,
    user_name: String,
    user_display_name: String,
    /// `required`, `preferred`, or `discouraged`: whether the site asks the
    /// owner to be verified.
    verification: &'static str,
    /// To sign in: the passkeys the vault holds for the site.
    pub(crate) passkeys: Vec<FillPasskey>,
    /// For a new passkey: the logins of the site it may go on.
    pub(crate) logins: Vec<FillLogin>,
    /// This computer can check the owner itself (on macOS, Touch ID or the
    /// Mac's password); otherwise the vault's password does.
    owner_check: bool,
}

/// What the owner is asked.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillAsked {
    pub(crate) request_id: String,
    pub(crate) origin: String,
    browser: &'static str,
    seconds_left: u64,
    /// Names the unlock the logins were listed under; `None` while the
    /// vault is locked or missing. Handed back with the owner's choice.
    pub(crate) session: Option<String>,
    pub(crate) logins: Vec<FillLogin>,
    pub(crate) not_offered: Vec<NotOffered>,
    /// For a card form instead of a login form.
    pub(crate) card: Option<CardAsked>,
    /// For a page's request for a passkey.
    pub(crate) passkey: Option<PasskeyAsked>,
}

/// Logins whose address would have the page's origin if it were written
/// with `https://`. They cannot be filled; this only lets the app say why.
fn not_offered(vault: &Vault, origin: &str) -> Vec<NotOffered> {
    let Some(origin) = Origin::parse(origin) else {
        return Vec::new();
    };
    let Ok(items) = vault.list() else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter(|item| item.kind == ItemKind::Login)
        .filter_map(|item| {
            let address = item.url.trim();
            let (rest, reason) = match address.strip_prefix("http://") {
                Some(rest) => (rest, "not_https"),
                None if !address.is_empty() && !address.contains("://") => (address, "no_scheme"),
                None => return None,
            };
            (Origin::of_url(&format!("https://{rest}")).as_ref() == Some(&origin)).then(|| {
                NotOffered {
                    title: item.title.clone(),
                    url: item.url.clone(),
                    reason,
                }
            })
        })
        .collect()
}

/// The request waiting for the owner, if there is one.
#[tauri::command]
pub async fn fill_request(
    state: tauri::State<'_, AppState>,
) -> Result<Option<FillAsked>, CommandError> {
    let vault = state.vault.lock().await;
    let Some(choices) = state.browser.desk.choices(vault.as_ref())? else {
        return Ok(None);
    };
    let not_offered = match vault.as_ref() {
        Some(vault)
            if choices.session.is_some() && choices.card.is_none() && choices.passkey.is_none() =>
        {
            not_offered(vault, &choices.origin)
        }
        _ => Vec::new(),
    };
    let card = choices.card.map(|card| CardAsked {
        documents: card
            .frames
            .into_iter()
            .map(|frame| CardDocument {
                origin: frame.origin,
                page: frame.frame_id == 0,
                fields: frame.fields,
            })
            .collect(),
        cards: card
            .cards
            .into_iter()
            .map(|item| FillCard {
                id: item.id,
                title: item.title,
                brand: item.brand,
                ending: item.card_ending,
            })
            .collect(),
    });
    let fill_login = |login: &osm_vault_core::ItemSummary| FillLogin {
        id: login.id.clone(),
        title: login.title.clone(),
        username: login.username.clone(),
        url: login.url.clone(),
        conflict: login.conflict,
    };
    let passkey = choices.passkey.map(|asked| PasskeyAsked {
        ceremony: asked.ceremony,
        verification: match asked.verification {
            UserVerification::Required => "required",
            UserVerification::Preferred => "preferred",
            UserVerification::Discouraged => "discouraged",
        },
        passkeys: asked
            .passkeys
            .into_iter()
            .map(|found| FillPasskey {
                item_id: found.item_id,
                title: found.title,
                credential_id: found.passkey.credential_id,
                user_name: found.passkey.user_name,
                user_display_name: found.passkey.user_display_name,
            })
            .collect(),
        logins: asked.logins.iter().map(fill_login).collect(),
        rp_id: asked.rp_id,
        rp_name: asked.rp_name,
        user_name: asked.user_name,
        user_display_name: asked.user_display_name,
        owner_check: osm_desktop_session::can_check_owner(),
    });
    Ok(Some(FillAsked {
        session: choices.session.map(|session| session.to_string()),
        logins: choices
            .logins
            .iter()
            .map(|login| FillLogin {
                id: login.id.clone(),
                title: login.title.clone(),
                username: login.username.clone(),
                url: login.url.clone(),
                conflict: login.conflict,
            })
            .collect(),
        not_offered,
        card,
        passkey,
        request_id: choices.request_id,
        origin: choices.origin,
        browser: choices.browser,
        seconds_left: choices.seconds_left,
    }))
}

/// The owner chose a login for the waiting request. `session` is the one
/// the choices came with: a vault that locked since releases nothing.
#[tauri::command]
pub async fn approve_fill<R: Runtime>(
    request_id: String,
    item_id: String,
    session: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let locked = || CommandError {
        code: "locked",
        message: "the vault locked before the login was sent".into(),
    };
    {
        let vault = state.vault.lock().await;
        let vault = vault.as_ref().ok_or_else(locked)?;
        let session = session.parse().map_err(|_| locked())?;
        state
            .browser
            .desk
            .approve(&request_id, &item_id, session, vault)
            .map_err(|refused| match refused {
                Refused::Locked => locked(),
                // Only a passkey's choice is refused for the other two.
                Refused::NotPending | Refused::NotVerified | Refused::Exists => fill_ended(),
                Refused::NotForThisPage => CommandError {
                    code: "not_for_this_page",
                    message: "that item is not a login for this page".into(),
                },
                Refused::Vault(error) => error.into(),
            })?;
    }
    step_back(&app, &request_id);
    Ok(())
}

/// The owner chose a card for the waiting card's request, as
/// [`approve_fill`] a login.
#[tauri::command]
pub async fn approve_card<R: Runtime>(
    request_id: String,
    item_id: String,
    session: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let locked = || CommandError {
        code: "locked",
        message: "the vault locked before the card was sent".into(),
    };
    {
        let vault = state.vault.lock().await;
        let vault = vault.as_ref().ok_or_else(locked)?;
        let session = session.parse().map_err(|_| locked())?;
        state
            .browser
            .desk
            .approve_card(&request_id, &item_id, session, vault)
            .map_err(|refused| match refused {
                Refused::Locked => locked(),
                // Only a passkey's choice is refused for the other two.
                Refused::NotPending | Refused::NotVerified | Refused::Exists => fill_ended(),
                Refused::NotForThisPage => CommandError {
                    code: "not_a_card",
                    message: "that item is not a card that can be filled".into(),
                },
                Refused::Vault(error) => error.into(),
            })?;
    }
    step_back(&app, &request_id);
    Ok(())
}

/// The owner's choice for the waiting passkey's request: to save a new
/// one, `into` names a login of the site, or none for a new login; to sign
/// in, `item_id` and `credential_id` name the passkey. When the site asks
/// to verify the owner, the owner is verified now: by the system when
/// `owner_check` (Touch ID or the Mac's password), or by this device's
/// `password`; neither is kept. `session` as for [`approve_fill`].
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn approve_passkey<R: Runtime>(
    request_id: String,
    session: String,
    into: Option<String>,
    item_id: Option<String>,
    credential_id: Option<String>,
    password: Option<String>,
    owner_check: bool,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let password = password.map(Zeroizing::new);
    let locked = || CommandError {
        code: "locked",
        message: "the vault locked before the passkey was sent".into(),
    };
    let parsed_session: osm_vault_core::UnlockSession = session.parse().map_err(|_| locked())?;
    // Verify the vault is still unlocked under `session` before launching any
    // OS biometric/owner prompt.
    {
        let vault = state.vault.lock().await;
        if vault.as_ref().and_then(Vault::unlock_session) != Some(parsed_session) {
            return Err(locked());
        }
    }
    // Snapshot the monotonic ticket, ceremony, origin, and RP ID before any
    // async owner check so a swapped or replayed request cannot consume it.
    let (ticket, ceremony, origin, rp_id) = state
        .browser
        .desk
        .pending_passkey(&request_id)
        .ok_or_else(fill_ended)?;
    let not_verified = || CommandError {
        code: "not_verified",
        message: "you were not verified".into(),
    };
    // The system's check, before the vault is held: the owner may take a
    // while over it. Watch desk changes concurrently so if the browser request
    // disappears mid-prompt we invalidate the OS prompt immediately.
    let checked = if owner_check {
        let reason = match ceremony {
            Ceremony::Create => format!("save a passkey for {rp_id}"),
            Ceremony::Get => format!("sign in to {rp_id} with a passkey"),
        };
        let mut changes = state.browser.desk.changes();
        let (passed, mut said) = tokio::sync::oneshot::channel();
        let owner_check_guard = osm_desktop_session::check_owner(&reason, move |result| {
            let _ = passed.send(result);
        });
        let verified = loop {
            tokio::select! {
                result = &mut said => break result.unwrap_or(false),
                changed = changes.changed() => {
                    if changed.is_err() || !state.browser.desk.is_pending_ticket(ticket) {
                        owner_check_guard.cancel();
                        return Err(fill_ended());
                    }
                }
            }
        };
        drop(owner_check_guard);
        if !verified {
            return Err(not_verified());
        }
        true
    } else {
        false
    };
    {
        let mut vault = state.vault.lock().await;
        let vault = vault.as_mut().ok_or_else(locked)?;
        if vault.unlock_session() != Some(parsed_session) {
            return Err(locked());
        }
        let verified = checked
            || match &password {
                Some(password) => {
                    vault.check_password(password).map_err(|_| CommandError {
                        code: "wrong_password",
                        message: "that is not this device's password".into(),
                    })?;
                    true
                }
                None => false,
            };
        let desk = &state.browser.desk;
        let outcome = match ceremony {
            Ceremony::Create => desk.approve_passkey_create_bound(
                ticket,
                &request_id,
                &origin,
                &rp_id,
                parsed_session,
                vault,
                into.as_deref(),
                verified,
            ),
            Ceremony::Get => {
                let (Some(item), Some(credential)) = (&item_id, &credential_id) else {
                    return Err(CommandError {
                        code: "not_for_this_page",
                        message: "choose a passkey".into(),
                    });
                };
                desk.approve_passkey_get_bound(
                    ticket,
                    &request_id,
                    &origin,
                    &rp_id,
                    parsed_session,
                    vault,
                    item,
                    credential,
                    verified,
                )
            }
        };
        outcome.map_err(|refused| match refused {
            Refused::Locked => locked(),
            Refused::NotPending => fill_ended(),
            Refused::NotVerified => not_verified(),
            Refused::NotForThisPage => CommandError {
                code: "not_for_this_page",
                message: "that is not a passkey or a login for this site".into(),
            },
            Refused::Exists => {
                step_back(&app, &request_id);
                CommandError {
                    code: "passkey_exists",
                    message: "the site already has a passkey of this vault for the account".into(),
                }
            }
            Refused::Vault(error) => error.into(),
        })?;
    }
    step_back(&app, &request_id);
    Ok(())
}

/// The owner chose the browser's own passkeys for the waiting passkey's
/// request.
#[tauri::command]
pub async fn use_browser_passkey<R: Runtime>(
    request_id: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    if !state.browser.desk.use_browser(&request_id) {
        return Err(fill_ended());
    }
    step_back(&app, &request_id);
    Ok(())
}

fn fill_ended() -> CommandError {
    CommandError {
        code: "fill_ended",
        message: "the browser no longer waits for this".into(),
    }
}

/// The owner turned the waiting request down.
#[tauri::command]
pub async fn deny_fill<R: Runtime>(
    request_id: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    if !state.browser.desk.deny(&request_id) {
        return Err(fill_ended());
    }
    step_back(&app, &request_id);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserInfo {
    pub(crate) id: &'static str,
    name: &'static str,
    /// `connected`, `not_connected`, or `other`: the browser has a manifest
    /// under the host's name that is not the one this app would write.
    pub(crate) state: &'static str,
    /// The manifest's file.
    pub(crate) manifest: String,
    /// For `other`: the program that manifest names, if it names one.
    pub(crate) points_to: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    /// Whether this system can serve the browser at all.
    supported: bool,
    /// Whether the app is listening for the host.
    pub(crate) listening: bool,
    /// Why it is not, if it is not.
    pub(crate) problem: Option<String>,
    /// The host program a browser would be pointed at, if it was found.
    pub(crate) host: Option<String>,
    /// The host is in a place that is gone when the app quits, so no
    /// browser can be pointed at it.
    pub(crate) temporary_place: bool,
    /// The browsers found on this account.
    pub(crate) browsers: Vec<BrowserInfo>,
}

/// Whether the app is listening, and which browsers know where the host is.
#[tauri::command]
pub async fn browser_status(
    state: tauri::State<'_, AppState>,
) -> Result<BrowserStatus, CommandError> {
    Ok(state.browser.status())
}

fn storage(error: std::io::Error) -> CommandError {
    CommandError {
        code: "storage",
        message: error.to_string(),
    }
}

/// Tells a browser where the host is, so that its extension can reach this
/// app: writes the host's manifest into the browser's folder, replacing one
/// that is there under the same name.
#[tauri::command]
pub async fn connect_browser(
    browser: String,
    state: tauri::State<'_, AppState>,
) -> Result<BrowserStatus, CommandError> {
    let (known, home) = state.browser.known(&browser)?;
    let host = state.browser.host.as_ref().ok_or_else(|| CommandError {
        code: "host_missing",
        message: "the program browsers start was not found beside this app".into(),
    })?;
    if is_passing(host) {
        return Err(CommandError {
            code: "temporary_place",
            message: "the app is running from a place that is gone when it quits".into(),
        });
    }
    let manifest =
        serde_json::to_vec_pretty(&known.manifest(host)).map_err(|error| CommandError {
            code: "storage",
            message: error.to_string(),
        })?;
    known.connect(home, &manifest).map_err(storage)?;
    Ok(state.browser.status())
}

/// Takes the host's manifest out of a browser's folder: its extension can
/// no longer reach this app.
#[tauri::command]
pub async fn disconnect_browser(
    browser: String,
    state: tauri::State<'_, AppState>,
) -> Result<BrowserStatus, CommandError> {
    let (known, home) = state.browser.known(&browser)?;
    known.disconnect(home).map_err(storage)?;
    Ok(state.browser.status())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_is_there_when_any_of_its_folders_is() {
        let firefox = Known {
            id: "firefox",
            name: "Firefox",
            firefox: true,
            profiles: &[".mozilla/firefox", ".config/mozilla/firefox"],
            hosts: ".mozilla/native-messaging-hosts",
        };
        let home = tempfile::tempdir().unwrap();
        assert!(!firefox.used(home.path()));
        // Only the folder a new Firefox makes on Linux.
        std::fs::create_dir_all(home.path().join(".config/mozilla/firefox")).unwrap();
        assert!(firefox.used(home.path()));
        // Linux's own list has both, and the manifests where Firefox reads them.
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let known = BROWSERS.iter().find(|known| known.id == "firefox").unwrap();
            assert_eq!(known.profiles, firefox.profiles);
            assert_eq!(known.hosts, firefox.hosts);
        }
    }

    /// A browser's way to the host on Windows is a registry value, under a
    /// key of the test's own.
    #[cfg(windows)]
    #[test]
    fn a_browser_is_told_where_the_manifest_is_in_the_registry() {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};

        let known = Known {
            id: "test",
            name: "Test",
            firefox: false,
            profiles: &[],
            hosts: r"Software\OpenSecretManagerTest\NativeMessagingHosts",
        };
        let home = tempfile::tempdir().unwrap();
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let _ = root.delete_subkey_all(r"Software\OpenSecretManagerTest");

        assert_eq!(known.found(home.path()), None);
        known.connect(home.path(), b"{}").unwrap();
        let path = known.found(home.path()).unwrap();
        assert_eq!(path, known.manifest_path(home.path()));
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        // Connecting again replaces it.
        known.connect(home.path(), b"{\"again\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"again\":1}");

        known.disconnect(home.path()).unwrap();
        assert_eq!(known.found(home.path()), None);
        assert!(!path.exists());
        // Nothing to take away is no error.
        known.disconnect(home.path()).unwrap();
        let _ = root.delete_subkey_all(r"Software\OpenSecretManagerTest");
    }
}
