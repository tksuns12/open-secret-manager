//! The app's browser session through its real commands and events. The
//! mock runtime stands in for the window; a test plays the native messaging
//! host on the session's socket.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use osm_browser_link::{
    endpoint,
    frame::{self, Prefix},
    Caller, FillRequest, Forwarded, Refusal, Response, Waiting, CHROMIUM_EXTENSION_ID,
    FIREFOX_EXTENSION_ID, VERSION,
};
use osm_vault_core::{Item, ItemKind, Vault};
use tauri::{
    test::{mock_builder, mock_context, noop_assets, MockRuntime},
    App, AppHandle, Listener, Manager,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
    time::timeout,
};

use crate::{browser, network, AppState};

const PASSWORD: &str = "device password";
const PATIENCE: Duration = Duration::from_secs(30);

/// A folder with a path short enough for a socket.
fn folder() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("osm")
        .tempdir_in("/tmp")
        .unwrap()
}

fn shell(dir: &Path, home: &Path, host: Option<PathBuf>) -> App<MockRuntime> {
    let path = dir.join("vault.sqlite3");
    let network = network::Network::open(&path).unwrap();
    mock_builder()
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            archive: Mutex::new(None),
            browser: browser::Browser::with(&path, Some(home.to_owned()), host),
            path,
            network,
            chosen_backup: std::sync::Mutex::new(None),
            import: Mutex::new(None),
        })
        .build(mock_context(noop_assets()))
        .unwrap()
}

fn login(title: &str, address: &str) -> Item {
    let mut item = Item::new(title);
    item.username = format!("{title}@example.test");
    item.password = format!("{title} password");
    item.url = address.into();
    item
}

async fn unlock(app: &AppHandle<MockRuntime>) {
    let state = app.state::<AppState>();
    let mut vault = state.vault.lock().await;
    vault.as_mut().unwrap().unlock(PASSWORD).unwrap();
}

fn request(id: &str, origin: &str) -> Forwarded {
    Forwarded {
        caller: Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")),
        request: FillRequest {
            version: VERSION,
            request_id: id.into(),
            tab_id: 4,
            frame_id: 0,
            document_id: format!("document-of-{id}"),
            origin: origin.into(),
        },
    }
}

/// The host's end of one connection to the app.
struct Host(UnixStream);

impl Host {
    /// Connects and brings one request.
    async fn bring(dir: &Path, forwarded: &Forwarded) -> Self {
        let mut stream = UnixStream::connect(endpoint::socket_in(dir)).await.unwrap();
        let body = frame::encode(forwarded).unwrap();
        stream
            .write_all(&Prefix::Socket.frame(&body).unwrap())
            .await
            .unwrap();
        Self(stream)
    }

    /// The next response; `None` once the app closed the connection.
    async fn next(&mut self) -> Option<Response> {
        timeout(PATIENCE, async {
            let mut prefix = [0_u8; 4];
            self.0.read_exact(&mut prefix).await.ok()?;
            let mut body = vec![0_u8; Prefix::Socket.length(prefix).unwrap()];
            self.0.read_exact(&mut body).await.unwrap();
            Some(serde_json::from_slice(&body).unwrap())
        })
        .await
        .expect("the app answers or closes")
    }

    /// The next response besides the app's reminders that the request
    /// still waits; `None` once the app closed the connection.
    async fn answer(&mut self) -> Option<Response> {
        loop {
            match self.next().await {
                Some(Response::Waiting(_)) => continue,
                other => return other,
            }
        }
    }

    /// The app sends nothing for a while but its reminders, every 20
    /// seconds, that the request still waits.
    async fn is_quiet(&mut self) {
        let until = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            let mut prefix = [0_u8; 4];
            let Ok(read) = tokio::time::timeout_at(until, self.0.read_exact(&mut prefix)).await
            else {
                return;
            };
            let said = match read {
                Ok(_) => {
                    let mut body = vec![0_u8; Prefix::Socket.length(prefix).unwrap_or(0)];
                    let _ = self.0.read_exact(&mut body).await;
                    match serde_json::from_slice::<Response>(&body) {
                        Ok(Response::Waiting(_)) => continue,
                        _ => String::from_utf8_lossy(&body).into_owned(),
                    }
                }
                Err(error) => format!("(the connection ended: {error})"),
            };
            panic!("the app said something: {said}");
        }
    }
}

fn waiting(id: &str) -> Option<Response> {
    Some(Response::Waiting(Waiting {
        request_id: id.into(),
    }))
}

/// What the window would be shown, once the request `id` waits.
async fn asked(app: &AppHandle<MockRuntime>, id: &str) -> browser::FillAsked {
    for _ in 0..300 {
        if let Some(asked) = browser::fill_request(app.state()).await.unwrap() {
            if asked.request_id == id {
                return asked;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{id} never arrived");
}

async fn until_idle(app: &AppHandle<MockRuntime>) {
    for _ in 0..300 {
        if browser::fill_request(app.state()).await.unwrap().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the request never ended");
}

fn code<T>(result: Result<T, crate::CommandError>) -> &'static str {
    result.err().expect("a refusal").code
}

#[test]
fn a_request_from_the_browser_waits_in_the_app_for_the_owners_choice() {
    let dir = folder();
    let exact = login("exact", "https://example.com/login");
    let bare = login("bare", "example.com/login");
    let plain = login("plain", "http://example.com/");
    let mut note = login("note", "example.com");
    note.kind = ItemKind::SecureNote;
    let elsewhere = login("elsewhere", "https://www.example.com/");
    {
        let (mut vault, _) = Vault::create(dir.path().join("vault.sqlite3"), PASSWORD).unwrap();
        for item in [&exact, &bare, &plain, &note, &elsewhere] {
            vault.put(item.clone()).unwrap();
        }
    }
    // The app starts with its vault locked.
    let app = shell(dir.path(), dir.path(), None);
    let told = Arc::new(StdMutex::new(0_usize));
    let count = told.clone();
    app.listen_any("fill-request", move |_| *count.lock().unwrap() += 1);
    let handle = app.handle().clone();
    let folder = dir.path().to_owned();

    tauri::async_runtime::block_on(async move {
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert!(!status.listening);
        browser::start(&handle);
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert!(status.listening, "{:?}", status.problem);
        assert!(browser::fill_request(handle.state())
            .await
            .unwrap()
            .is_none());

        // A request arrives while the vault is locked: the window is told,
        // and shows the origin without any login.
        let wanted = request("first", "https://example.com");
        let mut host = Host::bring(&folder, &wanted).await;
        assert_eq!(host.next().await, waiting("first"));
        let shown = asked(&handle, "first").await;
        assert_eq!(shown.origin, "https://example.com");
        assert_eq!(shown.session, None);
        assert!(shown.logins.is_empty() && shown.not_offered.is_empty());
        // The window is told by a task of its own, which may run after the
        // request is already there to be read.
        for _ in 0..300 {
            if *told.lock().unwrap() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(*told.lock().unwrap() >= 2, "the window was told");
        // Nothing can be chosen while it is locked.
        assert_eq!(
            code(
                browser::approve_fill(
                    "first".into(),
                    exact.id.clone(),
                    "00".repeat(16),
                    handle.state(),
                    handle.clone()
                )
                .await
            ),
            "locked"
        );

        // Unlocked, it offers the one login for exactly that origin and
        // says which others it cannot offer and why.
        unlock(&handle).await;
        let shown = asked(&handle, "first").await;
        let first_unlock = shown.session.clone().unwrap();
        assert_eq!(shown.logins.len(), 1);
        assert_eq!(
            (shown.logins[0].id.as_str(), shown.logins[0].title.as_str()),
            (exact.id.as_str(), "exact")
        );
        let mut hints: Vec<(&str, &str)> = shown
            .not_offered
            .iter()
            .map(|login| (login.title.as_str(), login.reason))
            .collect();
        hints.sort();
        assert_eq!(hints, [("bare", "no_scheme"), ("plain", "not_https")]);
        // What the window is given holds no password.
        let json = serde_json::to_string(&shown).unwrap();
        assert!(!json.contains("password"), "{json}");

        // An item that is not offered cannot be sent by naming it.
        for item in [&bare, &plain, &note, &elsewhere] {
            assert_eq!(
                code(
                    browser::approve_fill(
                        "first".into(),
                        item.id.clone(),
                        first_unlock.clone(),
                        handle.state(),
                        handle.clone()
                    )
                    .await
                ),
                "not_for_this_page",
                "{}",
                item.title
            );
        }

        // The vault locks before the owner's choice arrives: nothing is
        // sent, also after unlocking again.
        crate::lock_vault(handle.state()).await.unwrap();
        let choose = |session: String| {
            browser::approve_fill(
                "first".into(),
                exact.id.clone(),
                session,
                handle.state(),
                handle.clone(),
            )
        };
        assert_eq!(code(choose(first_unlock.clone()).await), "locked");
        unlock(&handle).await;
        assert_eq!(code(choose(first_unlock.clone()).await), "locked");
        assert_eq!(code(choose("not a session".into()).await), "locked");
        host.is_quiet().await;

        // Chosen under the unlock it is shown in, the login goes to the
        // host, bound to the request.
        let shown = asked(&handle, "first").await;
        let second_unlock = shown.session.unwrap();
        assert_ne!(second_unlock, first_unlock);
        choose(second_unlock.clone()).await.unwrap();
        let Some(Response::FillReply(reply)) = host.answer().await else {
            panic!("a reply")
        };
        assert!(reply.answers(&wanted.request));
        assert_eq!(reply.username, "exact@example.test");
        assert_eq!(reply.password, "exact password");
        assert_eq!(host.next().await, None);
        until_idle(&handle).await;
        assert_eq!(code(choose(second_unlock.clone()).await), "fill_ended");

        // The owner turns the next one down.
        let mut host = Host::bring(&folder, &request("second", "https://www.example.com")).await;
        assert_eq!(host.next().await, waiting("second"));
        let shown = asked(&handle, "second").await;
        assert_eq!(shown.logins.len(), 1);
        assert_eq!(shown.logins[0].id, elsewhere.id);
        browser::deny_fill("second".into(), handle.state(), handle.clone())
            .await
            .unwrap();
        assert_eq!(
            host.answer().await,
            Some(Response::refusal("second", Refusal::Denied))
        );
        assert_eq!(
            code(browser::deny_fill("second".into(), handle.state(), handle.clone()).await),
            "fill_ended"
        );

        // The page goes away while its request waits.
        let host = Host::bring(&folder, &request("third", "https://example.com")).await;
        asked(&handle, "third").await;
        drop(host);
        until_idle(&handle).await;
        assert_eq!(
            code(
                browser::approve_fill(
                    "third".into(),
                    exact.id.clone(),
                    second_unlock,
                    handle.state(),
                    handle.clone()
                )
                .await
            ),
            "fill_ended"
        );

        // A request from anything but the allowed extension never waits.
        let mut forged = request("fourth", "https://example.com");
        forged.caller = Caller::Firefox("another@example.org".into());
        let mut host = Host::bring(&folder, &forged).await;
        assert_eq!(
            host.next().await,
            Some(Response::refusal("fourth", Refusal::ExtensionNotAllowed))
        );
        assert!(browser::fill_request(handle.state())
            .await
            .unwrap()
            .is_none());
    });
}

#[test]
fn a_device_without_a_vault_shows_the_request_and_can_only_deny_it() {
    let dir = folder();
    let app = shell(dir.path(), dir.path(), None);
    let handle = app.handle().clone();
    let folder = dir.path().to_owned();
    tauri::async_runtime::block_on(async move {
        browser::start(&handle);
        let mut host = Host::bring(&folder, &request("first", "https://example.com")).await;
        assert_eq!(host.next().await, waiting("first"));
        let shown = asked(&handle, "first").await;
        assert_eq!((shown.session, shown.logins.len()), (None, 0));
        assert_eq!(
            code(
                browser::approve_fill(
                    "first".into(),
                    "anything".into(),
                    "00".repeat(16),
                    handle.state(),
                    handle.clone()
                )
                .await
            ),
            "locked"
        );
        browser::deny_fill("first".into(), handle.state(), handle.clone())
            .await
            .unwrap();
        assert_eq!(
            host.answer().await,
            Some(Response::refusal("first", Refusal::Denied))
        );
    });
}

#[test]
fn a_second_copy_of_the_app_does_not_take_the_socket() {
    let dir = folder();
    let first = shell(dir.path(), dir.path(), None);
    let second = shell(dir.path(), dir.path(), None);
    let (first, second) = (first.handle().clone(), second.handle().clone());
    tauri::async_runtime::block_on(async move {
        browser::start(&first);
        browser::start(&second);
        assert!(
            browser::browser_status(first.state())
                .await
                .unwrap()
                .listening
        );
        let status = browser::browser_status(second.state()).await.unwrap();
        assert!(!status.listening);
        assert_eq!(
            status.problem.as_deref(),
            Some("another copy of this app is already listening")
        );
    });
}

/// The folders a browser has under a home folder on this system: its own,
/// and the one it reads host manifests from.
fn folders(home: &Path, browser: &str) -> (PathBuf, PathBuf) {
    let (own, hosts) = if cfg!(target_os = "macos") {
        let support = "Library/Application Support";
        match browser {
            "chrome" => (
                format!("{support}/Google/Chrome"),
                format!("{support}/Google/Chrome/NativeMessagingHosts"),
            ),
            "firefox" => (
                format!("{support}/Firefox"),
                format!("{support}/Mozilla/NativeMessagingHosts"),
            ),
            other => panic!("{other}"),
        }
    } else {
        match browser {
            "chrome" => (
                ".config/google-chrome".to_owned(),
                ".config/google-chrome/NativeMessagingHosts".to_owned(),
            ),
            "firefox" => (
                ".mozilla/firefox".to_owned(),
                ".mozilla/native-messaging-hosts".to_owned(),
            ),
            other => panic!("{other}"),
        }
    };
    (home.join(own), home.join(hosts))
}

#[test]
fn a_browser_is_connected_by_writing_the_hosts_manifest_into_its_folder() {
    let dir = folder();
    let home = dir.path().join("home");
    let host = dir.path().join("osm-native-host");
    std::fs::write(&host, b"").unwrap();
    for browser in ["chrome", "firefox"] {
        std::fs::create_dir_all(folders(&home, browser).0).unwrap();
    }
    let app = shell(dir.path(), &home, Some(host.clone()));
    let handle = app.handle().clone();

    tauri::async_runtime::block_on(async move {
        let state_of = |status: &browser::BrowserStatus| -> Vec<(&'static str, &'static str)> {
            status
                .browsers
                .iter()
                .map(|browser| (browser.id, browser.state))
                .collect()
        };
        // Only the browsers found under the home folder are listed.
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert_eq!(status.host.as_deref(), host.to_str());
        assert!(!status.temporary_place);
        assert_eq!(
            state_of(&status),
            [("chrome", "not_connected"), ("firefox", "not_connected")]
        );
        let manifest_of = |browser: &str| {
            folders(&home, browser)
                .1
                .join("org.opensecretmanager.native.json")
        };
        assert_eq!(
            status.browsers[0].manifest,
            manifest_of("chrome").to_string_lossy()
        );
        assert!(!manifest_of("chrome").exists());

        // Connecting writes the manifest each kind of browser expects: the
        // host's place and the one extension that may start it.
        let status = browser::connect_browser("chrome".into(), handle.state())
            .await
            .unwrap();
        assert_eq!(
            state_of(&status),
            [("chrome", "connected"), ("firefox", "not_connected")]
        );
        let read = |browser: &str| -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(manifest_of(browser)).unwrap()).unwrap()
        };
        assert_eq!(
            read("chrome"),
            serde_json::json!({
                "name": "org.opensecretmanager.native",
                "description": "Open Secret Manager native messaging host",
                "path": host,
                "type": "stdio",
                "allowed_origins": [format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")],
            })
        );
        browser::connect_browser("firefox".into(), handle.state())
            .await
            .unwrap();
        assert_eq!(
            read("firefox"),
            serde_json::json!({
                "name": "org.opensecretmanager.native",
                "description": "Open Secret Manager native messaging host",
                "path": host,
                "type": "stdio",
                "allowed_extensions": [FIREFOX_EXTENSION_ID],
            })
        );
        // Nothing but the manifest is left in the browser's folder.
        let left: Vec<_> = std::fs::read_dir(folders(&home, "chrome").1)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["org.opensecretmanager.native.json"]);

        // A manifest that names another program, or allows another
        // extension, is reported, and connecting again puts it right.
        let mut changed = read("chrome");
        changed["path"] = "/somewhere/else".into();
        std::fs::write(manifest_of("chrome"), changed.to_string()).unwrap();
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert_eq!(status.browsers[0].state, "other");
        assert_eq!(
            status.browsers[0].points_to.as_deref(),
            Some("/somewhere/else")
        );
        let mut widened = read("firefox");
        widened["allowed_extensions"] =
            serde_json::json!([FIREFOX_EXTENSION_ID, "another@example.org"]);
        std::fs::write(manifest_of("firefox"), widened.to_string()).unwrap();
        std::fs::write(manifest_of("chrome"), b"not json").unwrap();
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert_eq!(
            state_of(&status),
            [("chrome", "other"), ("firefox", "other")]
        );
        assert_eq!(status.browsers[0].points_to, None);
        for browser in ["chrome", "firefox"] {
            browser::connect_browser(browser.into(), handle.state())
                .await
                .unwrap();
        }
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert_eq!(
            state_of(&status),
            [("chrome", "connected"), ("firefox", "connected")]
        );

        // Disconnecting takes the manifest away, and doing it twice is fine.
        for _ in 0..2 {
            let status = browser::disconnect_browser("chrome".into(), handle.state())
                .await
                .unwrap();
            assert_eq!(
                state_of(&status),
                [("chrome", "not_connected"), ("firefox", "connected")]
            );
        }
        assert!(!manifest_of("chrome").exists());

        // A browser that is not on this account, or not a browser this app
        // knows, is refused.
        for browser in ["brave", "netscape", "../chrome", ""] {
            assert_eq!(
                code(browser::connect_browser(browser.into(), handle.state()).await),
                "no_browser",
                "{browser}"
            );
            assert_eq!(
                code(browser::disconnect_browser(browser.into(), handle.state()).await),
                "no_browser"
            );
        }
    });

    // Without the host program there is nothing to point a browser at.
    let app = shell(dir.path(), &dir.path().join("home"), None);
    let handle = app.handle().clone();
    tauri::async_runtime::block_on(async move {
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert_eq!(status.host, None);
        // The manifest that is still there is not this app's to vouch for.
        assert_eq!(status.browsers[1].state, "other");
        assert_eq!(
            code(browser::connect_browser("chrome".into(), handle.state()).await),
            "host_missing"
        );
    });
}

#[test]
fn a_packaged_app_finds_the_host_beside_its_own_program() {
    let dir = folder();
    let programs = dir.path().join("Open Secret Manager.app/Contents/MacOS");
    std::fs::create_dir_all(&programs).unwrap();
    let program = programs.join("open-secret-manager");
    std::fs::write(&program, b"").unwrap();
    assert_eq!(browser::host_beside(&program), None);
    // A folder of the host's name is not the host.
    std::fs::create_dir(programs.join("osm-native-host")).unwrap();
    assert_eq!(browser::host_beside(&program), None);
    std::fs::remove_dir(programs.join("osm-native-host")).unwrap();
    std::fs::write(programs.join("osm-native-host"), b"").unwrap();
    assert_eq!(
        browser::host_beside(&program),
        Some(programs.join("osm-native-host"))
    );
}

#[test]
fn a_browser_is_not_pointed_at_a_place_that_is_gone_when_the_app_quits() {
    let app_in = |folder: &str| {
        PathBuf::from(folder).join("Open Secret Manager.app/Contents/MacOS/osm-native-host")
    };
    for stays in [
        app_in("/Applications"),
        app_in("/Users/someone/Applications"),
        app_in("/Volumes/Another Disk/Apps"),
        PathBuf::from("/usr/bin/osm-native-host"),
    ] {
        assert!(!browser::is_passing(&stays), "{}", stays.display());
    }
    let passing = [
        app_in(
            "/private/var/folders/q7/x/T/AppTranslocation/9F0C7B6E-1E0B-4A7B-9C3D-1D2E3F4A5B6C/d",
        ),
        PathBuf::from("/tmp/.mount_Open SrT3k9/usr/bin/osm-native-host"),
    ];
    for passing in &passing {
        assert!(browser::is_passing(passing), "{}", passing.display());
    }

    // The app says so, and writes nothing into the browser's folder.
    let dir = folder();
    let home = dir.path().join("home");
    std::fs::create_dir_all(folders(&home, "chrome").0).unwrap();
    let app = shell(dir.path(), &home, Some(passing[0].clone()));
    let handle = app.handle().clone();
    tauri::async_runtime::block_on(async move {
        let status = browser::browser_status(handle.state()).await.unwrap();
        assert!(status.temporary_place);
        assert_eq!(status.browsers[0].state, "not_connected");
        assert_eq!(
            code(browser::connect_browser("chrome".into(), handle.state()).await),
            "temporary_place"
        );
        assert!(!folders(&home, "chrome").1.exists());
    });
}

#[test]
fn the_app_listens_where_the_host_looks() {
    let vault = crate::default_vault_path();
    assert_eq!(
        endpoint::socket_path().as_deref(),
        vault.parent().map(endpoint::socket_in).as_deref()
    );
}
