//! Importing another app's export through the commands' own code on the
//! mock runtime: what the window is told before the owner confirms,
//! nothing written until then, and nothing kept once the vault locks. The
//! vault is made and unlocked directly, so that no control plane starts
//! and keeps running after the test.

use osm_vault_core::{ImportFormat, Item, Vault};
use tauri::{AppHandle, Manager};

use crate::{
    import, lock_vault,
    network_tests::{shell, titles, PASSWORD},
    AppState,
};

async fn unlock(app: &AppHandle<tauri::test::MockRuntime>) {
    let state = app.state::<AppState>();
    let mut vault = state.vault.lock().await;
    vault.as_mut().unwrap().unlock(PASSWORD).unwrap();
}

const BITWARDEN: &str = r#"{
  "items": [
    {"type": 1, "name": "Forum", "notes": "", "favorite": false,
     "login": {"username": "me@forum.example.test", "password": "forum password",
               "uris": [{"uri": "https://forum.example.test"}]}},
    {"type": 2, "name": "Wi-Fi", "notes": "network password"},
    {"type": 3, "name": "Visa", "card": {"cardholderName": "Owner", "number": "4111111111111111"}},
    {"type": 4, "name": "Passport", "identity": {"firstName": "Owner"}},
    {"type": 9, "name": "Something new"}
  ]
}"#;

const CHROME: &str = "name,url,username,password,note\n\
Mail,https://mail.example.test,owner@example.test,mail password,\n\
Shop,https://shop.example.test,buyer,shop password,receipts\n";

const FIREFOX: &str = "url,username,password,httpRealm,formActionOrigin,guid\n\
https://news.example.test,reader,news password,,https://news.example.test,{1}\n";

fn code<T>(result: Result<T, crate::CommandError>) -> &'static str {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.code,
    }
}

#[test]
fn an_export_is_shown_before_it_is_added_and_dropped_when_the_vault_locks() {
    let dir = tempfile::tempdir().unwrap();
    // The vault has Mail already, under the same website and username.
    {
        let (mut vault, _) = Vault::create(dir.path().join("vault.sqlite3"), PASSWORD).unwrap();
        let mut mail = Item::new("Mail");
        mail.url = "https://mail.example.test".into();
        mail.username = "owner@example.test".into();
        vault.put(mail).unwrap();
    }
    let app = shell(dir.path());
    let handle = app.handle().clone();
    let files = tempfile::tempdir().unwrap();
    let write = |name: &str, contents: &str| {
        let path = files.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    };
    let bitwarden = write("bitwarden.json", BITWARDEN);
    let chrome = write("chrome.csv", CHROME);
    let firefox = write("firefox.csv", FIREFOX);

    tauri::async_runtime::block_on(async move {
        let state = handle.state::<AppState>();
        unlock(&handle).await;

        // What Bitwarden's export would add, by kind; an entry of a kind
        // this app does not know is skipped and said to be.
        let summary = import::preview_file(&state, &bitwarden, ImportFormat::BitwardenJson)
            .await
            .unwrap();
        assert_eq!(summary.file, "bitwarden.json");
        assert_eq!(
            (
                summary.items,
                summary.logins,
                summary.notes,
                summary.cards,
                summary.identities
            ),
            (4, 1, 1, 1, 1)
        );
        assert_eq!(summary.already, 0);
        assert_eq!(summary.warnings.len(), 1, "{:?}", summary.warnings);
        // Nothing of it is in the vault before the owner confirms.
        assert_eq!(titles(&handle).await, ["Mail"]);

        // Choosing another export replaces the first.
        let summary = import::preview_file(&state, &chrome, ImportFormat::ChromeCsv)
            .await
            .unwrap();
        assert_eq!((summary.items, summary.logins, summary.already), (2, 2, 1));
        assert_eq!(import::confirm(&state).await.unwrap(), 2);
        assert_eq!(titles(&handle).await, ["Mail", "Mail", "Shop"]);
        // A confirmation is used once.
        assert_eq!(code(import::confirm(&state).await), "no_import");

        // Locking drops an import not yet confirmed.
        import::preview_file(&state, &firefox, ImportFormat::FirefoxCsv)
            .await
            .unwrap();
        lock_vault(handle.state()).await.unwrap();
        assert!(state.import.lock().await.is_none());
        assert_eq!(
            code(import::preview_file(&state, &firefox, ImportFormat::FirefoxCsv).await),
            "locked"
        );
        unlock(&handle).await;
        assert_eq!(code(import::confirm(&state).await), "no_import");
        assert_eq!(titles(&handle).await, ["Mail", "Mail", "Shop"]);

        // A file that is not such an export, or none at all.
        assert_eq!(
            code(import::preview_file(&state, &chrome, ImportFormat::BitwardenJson).await),
            "invalid_import"
        );
        assert_eq!(
            code(
                import::preview_file(
                    &state,
                    &files.path().join("gone.csv"),
                    ImportFormat::ChromeCsv
                )
                .await
            ),
            "invalid_import"
        );
        let summary = import::preview_file(&state, &firefox, ImportFormat::FirefoxCsv)
            .await
            .unwrap();
        assert_eq!((summary.items, summary.logins), (1, 1));
        assert_eq!(import::confirm(&state).await.unwrap(), 1);
        assert_eq!(
            titles(&handle).await,
            ["Mail", "Mail", "Shop", "https://news.example.test"]
        );
    });
}
