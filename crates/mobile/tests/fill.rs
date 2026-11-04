//! What a phone fills and saves, decided in one place: a page gets only the
//! logins for its origins, an app only those the owner chose for it, and a
//! save goes only into a login the same form could be filled with. These
//! rules are proved here; the tests on the emulator and the simulator keep
//! one case for each way a fill or a save reaches the app.

use std::{collections::HashMap, path::PathBuf};

use osm_mobile::{Asks, CardDraft, Device, ItemDraft, ItemKind, MobileError, Offer, Requester};

const PASSWORD: &str = "fixture password, not a secret";
/// The test vector of RFC 6238 as a base32 secret.
const TOTP: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// A device on a copy of the frozen format 7 vault, unlocked. It holds the
/// logins Bank (`https://bank.example.test:8443`, with a one-time code),
/// Mail (`https://mail.example.test`), and Shared, in conflict.
fn device() -> (tempfile::TempDir, PathBuf, Device) {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("device");
    std::fs::create_dir_all(&folder).unwrap();
    let frozen = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vault-core/fixtures/format-7/vault.sqlite3");
    std::fs::copy(frozen, folder.join("vault.sqlite3")).unwrap();
    let device = Device::open_listening_on(folder.clone(), 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    (dir, folder, device)
}

fn login(device: &Device, title: &str, url: &str, username: &str) -> String {
    device
        .create_item(ItemDraft {
            title: title.into(),
            kind: ItemKind::Login,
            username: username.into(),
            url: url.into(),
            notes: String::new(),
            favorite: false,
            password: Some(format!("password of {title}")),
            one_time_code_secret: None,
            card: None,
        })
        .unwrap()
}

fn page(origins: &[&str]) -> Requester {
    Requester::Page {
        origins: origins.iter().map(|origin| (*origin).to_owned()).collect(),
    }
}

fn app(key: &str) -> Requester {
    Requester::App {
        key: key.into(),
        linked_domains: Vec::new(),
    }
}

fn titles(offer: Offer) -> (Vec<String>, Vec<String>) {
    let mut logins: Vec<String> = offer.logins.into_iter().map(|item| item.title).collect();
    let mut suggested: Vec<String> = offer.suggested.into_iter().map(|item| item.title).collect();
    logins.sort();
    suggested.sort();
    (logins, suggested)
}

fn offered(device: &Device, requester: Requester, asks: Asks) -> (Vec<String>, Vec<String>) {
    titles(device.offer(requester, asks).unwrap())
}

#[test]
fn a_page_is_offered_and_filled_only_the_logins_for_its_origins() {
    let (_dir, _folder, device) = device();
    assert_eq!(
        offered(&device, page(&["https://mail.example.test"]), Asks::Login),
        (vec!["Mail".to_owned()], vec![])
    );
    assert_eq!(
        offered(
            &device,
            page(&["https://bank.example.test:8443"]),
            Asks::Login
        )
        .0,
        ["Bank"]
    );
    for nothing in [
        "https://bank.example.test",
        "https://login.mail.example.test",
        "https://example.test",
    ] {
        assert_eq!(
            offered(&device, page(&[nothing]), Asks::Login),
            (vec![], vec![])
        );
    }
    // iOS names an app's verified domains as origins: one offer for all.
    assert_eq!(
        offered(
            &device,
            page(&[
                "https://mail.example.test",
                "https://bank.example.test:8443"
            ]),
            Asks::Login
        )
        .0,
        ["Bank", "Mail"]
    );

    let filled = device
        .fill(
            page(&["https://mail.example.test"]),
            "fixture-mail".into(),
            Asks::Login,
        )
        .unwrap();
    let credentials = filled.credentials.clone().unwrap();
    assert_eq!(
        (credentials.username.as_str(), credentials.password.as_str()),
        ("owner@example.test", "third password, with ünïcödé")
    );
    assert_eq!(filled.one_time_code, None);
    assert_eq!(format!("{filled:?}"), "Filled { .. }");
    // Whoever chose it, a page gets only its own logins.
    for fill in [Device::fill, Device::fill_chosen] {
        assert!(matches!(
            fill(
                &device,
                page(&["https://mail.example.test"]),
                "fixture-bank".into(),
                Asks::Login
            ),
            Err(MobileError::NotForThisPage)
        ));
    }
    assert!(device
        .fill(
            page(&[
                "https://mail.example.test",
                "https://bank.example.test:8443"
            ]),
            "fixture-bank".into(),
            Asks::Login
        )
        .is_ok());

    // Only https origins, exactly as a browser writes them; and some.
    for wrong in [
        "http://mail.example.test",
        "https://mail.example.test/",
        "mail.example.test",
    ] {
        assert!(
            matches!(
                device.offer(page(&[wrong]), Asks::Login),
                Err(MobileError::InvalidOrigin)
            ),
            "{wrong}"
        );
        assert!(
            matches!(
                device.fill(page(&[wrong]), "fixture-mail".into(), Asks::Login),
                Err(MobileError::InvalidOrigin)
            ),
            "{wrong}"
        );
    }
    assert!(matches!(
        device.offer(page(&[]), Asks::Login),
        Err(MobileError::InvalidRequester)
    ));
}

#[test]
fn an_app_is_filled_only_a_login_the_owner_chose_for_it_and_this_phone_remembers_it() {
    let (_dir, folder, device) = device();
    let chat = app("org.example.chat:AB12");
    assert_eq!(
        offered(&device, chat.clone(), Asks::Login),
        (vec![], vec![])
    );
    // Not chosen yet: any login the app names is refused.
    assert!(matches!(
        device.fill(chat.clone(), "fixture-mail".into(), Asks::Login),
        Err(MobileError::NotChosen)
    ));
    // The owner chooses among every login, or for a code alone, those with
    // a code.
    let mut every: Vec<String> = device
        .logins_to_choose(Asks::Login)
        .unwrap()
        .into_iter()
        .map(|item| item.id)
        .collect();
    let mut logins: Vec<String> = device
        .items()
        .unwrap()
        .into_iter()
        .filter(|item| item.kind == ItemKind::Login)
        .map(|item| item.id)
        .collect();
    every.sort();
    logins.sort();
    assert_eq!(every, logins);
    let with_codes: Vec<String> = device
        .logins_to_choose(Asks::OneTimeCode)
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    assert_eq!(with_codes, ["Bank"]);

    // The owner chooses one on the phone's screen: filled, and the app's.
    let filled = device
        .fill_chosen(chat.clone(), "fixture-mail".into(), Asks::Login)
        .unwrap();
    assert_eq!(filled.credentials.unwrap().username, "owner@example.test");
    assert_eq!(offered(&device, chat.clone(), Asks::Login).0, ["Mail"]);
    assert!(device
        .fill(chat.clone(), "fixture-mail".into(), Asks::Login)
        .is_ok());
    assert!(matches!(
        device.fill(chat.clone(), "fixture-bank".into(), Asks::Login),
        Err(MobileError::NotChosen)
    ));

    // Another app, or the same package signed by someone else, is another
    // key: it is offered nothing.
    let other = app("org.example.chat:CD34");
    assert_eq!(
        offered(&device, other.clone(), Asks::Login),
        (vec![], vec![])
    );
    assert!(matches!(
        device.fill(other, "fixture-mail".into(), Asks::Login),
        Err(MobileError::NotChosen)
    ));

    // Only logins are filled, chosen or not.
    let note = ItemDraft {
        title: "Recovery codes".into(),
        kind: ItemKind::SecureNote,
        username: String::new(),
        url: String::new(),
        notes: "one".into(),
        favorite: false,
        password: None,
        one_time_code_secret: None,
        card: None,
    };
    let note = device.create_item(note).unwrap();
    assert!(matches!(
        device.fill_chosen(chat.clone(), note, Asks::Login),
        Err(MobileError::NotALogin)
    ));
    assert!(matches!(
        device.fill_chosen(chat.clone(), "no such item".into(), Asks::Login),
        Err(MobileError::NotFound)
    ));
    assert_eq!(offered(&device, chat.clone(), Asks::Login).0, ["Mail"]);
    assert!(matches!(
        device.offer(app(""), Asks::Login),
        Err(MobileError::InvalidRequester)
    ));

    // On this phone only, kept beside the vault, through a restart.
    let kept: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("app-logins.json")).unwrap()).unwrap();
    assert_eq!(
        kept,
        serde_json::json!({"org.example.chat:AB12": ["fixture-mail"]})
    );
    drop(device);
    let device = Device::open_listening_on(folder, 0).unwrap();
    assert!(matches!(
        device.offer(chat.clone(), Asks::Login),
        Err(MobileError::Locked)
    ));
    assert!(matches!(
        device.fill(chat.clone(), "fixture-mail".into(), Asks::Login),
        Err(MobileError::Locked)
    ));
    device.unlock(PASSWORD.into()).unwrap();
    assert_eq!(offered(&device, chat, Asks::Login).0, ["Mail"]);
}

#[test]
fn the_logins_of_the_sites_an_app_is_verified_for_are_suggested_until_one_is_chosen() {
    let (_dir, _folder, device) = device();
    login(&device, "Shop", "https://shop.example.org/login", "buyer");
    login(
        &device,
        "Shop account",
        "https://account.shop.example.org",
        "buyer",
    );
    login(
        &device,
        "Shop staging",
        "https://shop.example.org:8443",
        "buyer",
    );
    login(
        &device,
        "Shop over http",
        "http://shop.example.org",
        "buyer",
    );
    login(
        &device,
        "Look-alike",
        "https://shop.example.org.evil.test",
        "buyer",
    );
    let shop = Requester::App {
        key: "org.example.shop:EF56".into(),
        // As Android lists them, a wildcard and `www.` among them.
        linked_domains: vec![
            "*.Shop.example.org".into(),
            "www.shop.example.org".into(),
            "localhost".into(),
        ],
    };
    assert_eq!(
        offered(&device, shop.clone(), Asks::Login),
        (vec![], vec!["Shop".to_owned(), "Shop account".to_owned()])
    );
    // A suggestion fills nothing until the owner chooses it.
    let suggestion = device.offer(shop.clone(), Asks::Login).unwrap().suggested[0]
        .id
        .clone();
    assert!(matches!(
        device.fill(shop.clone(), suggestion.clone(), Asks::Login),
        Err(MobileError::NotChosen)
    ));
    device
        .fill_chosen(shop.clone(), suggestion, Asks::Login)
        .unwrap();
    let (logins, suggested) = offered(&device, shop, Asks::Login);
    assert_eq!(logins.len(), 1);
    assert_eq!(suggested.len(), 1);
    assert_ne!(logins, suggested);
}

#[test]
fn a_request_that_names_no_one_is_offered_nothing_and_filled_only_the_owners_choice() {
    let (_dir, folder, device) = device();
    assert_eq!(
        offered(&device, Requester::Unnamed, Asks::Login),
        (vec![], vec![])
    );
    assert!(matches!(
        device.fill(Requester::Unnamed, "fixture-mail".into(), Asks::Login),
        Err(MobileError::NotChosen)
    ));
    let filled = device
        .fill_chosen(Requester::Unnamed, "fixture-mail".into(), Asks::Login)
        .unwrap();
    assert_eq!(filled.credentials.unwrap().username, "owner@example.test");
    // Nothing is remembered for no one.
    assert_eq!(
        offered(&device, Requester::Unnamed, Asks::Login),
        (vec![], vec![])
    );
    assert!(!folder.join("app-logins.json").exists());
}

#[test]
fn a_form_is_filled_only_what_it_asks_for_and_a_code_only_where_its_login_would_go() {
    let (_dir, _folder, device) = device();
    let bank = page(&["https://bank.example.test:8443"]);
    let mail = page(&["https://mail.example.test"]);
    // A form that asks for a code alone is offered only logins with one.
    assert_eq!(
        offered(&device, bank.clone(), Asks::OneTimeCode).0,
        ["Bank"]
    );
    assert!(offered(&device, mail.clone(), Asks::OneTimeCode)
        .0
        .is_empty());
    assert_eq!(
        offered(&device, mail.clone(), Asks::LoginAndOneTimeCode).0,
        ["Mail"]
    );

    let code_only = device
        .fill(bank.clone(), "fixture-bank".into(), Asks::OneTimeCode)
        .unwrap();
    assert!(code_only.credentials.is_none());
    let code = code_only.one_time_code.unwrap();
    assert!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()));
    let both = device
        .fill(
            bank.clone(),
            "fixture-bank".into(),
            Asks::LoginAndOneTimeCode,
        )
        .unwrap();
    assert_eq!(both.credentials.unwrap().username, "account 42");
    assert!(both.one_time_code.is_some());
    assert!(device
        .fill(bank.clone(), "fixture-bank".into(), Asks::Login)
        .unwrap()
        .one_time_code
        .is_none());
    // A login without a code: with the password it fills without one;
    // alone, there is nothing to fill.
    let without = device
        .fill(
            mail.clone(),
            "fixture-mail".into(),
            Asks::LoginAndOneTimeCode,
        )
        .unwrap();
    assert!(without.credentials.is_some() && without.one_time_code.is_none());
    assert!(matches!(
        device.fill(mail, "fixture-mail".into(), Asks::OneTimeCode),
        Err(MobileError::NoOneTimeCode)
    ));
    // A code goes only where its login would.
    assert!(matches!(
        device.fill(
            page(&["https://bank.example.test"]),
            "fixture-bank".into(),
            Asks::OneTimeCode
        ),
        Err(MobileError::NotForThisPage)
    ));

    // For an app, the code of a login chosen for it.
    let authenticator = app("org.example.bank:0011");
    let with_code = ItemDraft {
        title: "Bank app".into(),
        kind: ItemKind::Login,
        username: "account 42".into(),
        url: String::new(),
        notes: String::new(),
        favorite: false,
        password: Some("app password".into()),
        one_time_code_secret: Some(TOTP.into()),
        card: None,
    };
    let id = device.create_item(with_code).unwrap();
    assert!(matches!(
        device.fill(authenticator.clone(), id.clone(), Asks::OneTimeCode),
        Err(MobileError::NotChosen)
    ));
    device
        .fill_chosen(authenticator.clone(), id.clone(), Asks::Login)
        .unwrap();
    assert_eq!(
        offered(&device, authenticator.clone(), Asks::OneTimeCode).0,
        ["Bank app"]
    );
    assert!(device
        .fill(authenticator, id, Asks::OneTimeCode)
        .unwrap()
        .one_time_code
        .is_some());
}

#[test]
fn any_requester_is_offered_and_filled_the_cards_not_in_conflict() {
    let (_dir, _folder, device) = device();
    assert!(device.offer_cards().unwrap().is_empty());
    let card = device
        .create_item(ItemDraft {
            title: "Visa".into(),
            kind: ItemKind::Card,
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            favorite: false,
            password: None,
            one_time_code_secret: None,
            card: Some(CardDraft {
                cardholder: "Owner".into(),
                expiry_month: "09".into(),
                expiry_year: "2031".into(),
                brand: None,
                number: Some("4111 1111 1111 1111".into()),
                security_code: Some("123".into()),
            }),
        })
        .unwrap();
    let cards = device.offer_cards().unwrap();
    assert_eq!(
        cards
            .iter()
            .map(|card| card.title.as_str())
            .collect::<Vec<_>>(),
        ["Visa"]
    );
    assert_eq!(cards[0].card_ending.as_deref(), Some("1111"));
    let filled = device.fill_card(card).unwrap();
    assert_eq!(
        (
            filled.cardholder.as_str(),
            filled.number.as_str(),
            filled.expiry_month.as_str(),
            filled.expiry_year.as_str(),
            filled.security_code.as_str()
        ),
        ("Owner", "4111111111111111", "09", "2031", "123")
    );
    assert_eq!(format!("{filled:?}"), "CardFill { .. }");
    assert!(matches!(
        device.fill_card("fixture-bank".into()),
        Err(MobileError::NotACard)
    ));
}

#[test]
fn a_save_goes_only_into_a_login_the_same_form_could_be_filled_with() {
    let (_dir, _folder, device) = device();
    let mail = page(&["https://mail.example.test"]);
    let candidates = |requester: Requester, username: &str, password: &str| {
        device
            .save_candidates_for(requester, username.into(), password.into())
            .unwrap()
            .into_iter()
            .map(|candidate| (candidate.title, candidate.has_this_password))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        candidates(mail.clone(), " owner@example.test ", "a new password"),
        [("Mail".to_owned(), false)]
    );
    assert_eq!(
        candidates(
            mail.clone(),
            "owner@example.test",
            "third password, with ünïcödé"
        ),
        [("Mail".to_owned(), true)]
    );
    // Another username is another account; a form without one could be
    // any of the page's.
    assert!(candidates(mail.clone(), "someone else", "x").is_empty());
    assert_eq!(
        candidates(mail.clone(), "", "x"),
        [("Mail".to_owned(), false)]
    );
    assert!(candidates(page(&["https://example.test"]), "", "x").is_empty());
    // An app's are those chosen for it, not in conflict; no one's, none.
    let chat = app("org.example.chat:AB12");
    assert!(candidates(chat.clone(), "", "x").is_empty());
    device
        .fill_chosen(chat.clone(), "fixture-mail".into(), Asks::Login)
        .unwrap();
    device
        .fill_chosen(chat.clone(), "fixture-shared".into(), Asks::Login)
        .unwrap();
    assert_eq!(
        candidates(chat.clone(), "", "x"),
        [("Mail".to_owned(), false)]
    );
    assert!(candidates(Requester::Unnamed, "", "x").is_empty());

    // An update goes only into one of those.
    let bank = device.item("fixture-bank".into()).unwrap();
    let mail_item = device.item("fixture-mail".into()).unwrap();
    for (requester, id, username) in [
        (mail.clone(), "fixture-bank", ""),
        (mail.clone(), "fixture-mail", "someone else"),
        (app("org.example.other:99"), "fixture-mail", ""),
        (Requester::Unnamed, "fixture-mail", ""),
    ] {
        let revision = if id == "fixture-bank" {
            &bank.revision
        } else {
            &mail_item.revision
        };
        assert!(
            matches!(
                device.update_saved(
                    requester.clone(),
                    id.into(),
                    revision.clone(),
                    username.into(),
                    "x".into()
                ),
                Err(MobileError::NotForThisForm)
            ),
            "{requester:?} {id} {username}"
        );
    }
    // The password changes, and nothing else.
    device
        .update_saved(
            chat.clone(),
            "fixture-mail".into(),
            mail_item.revision.clone(),
            "owner@example.test".into(),
            "a new password".into(),
        )
        .unwrap();
    assert_eq!(
        device.password("fixture-mail".into()).unwrap(),
        "a new password"
    );
    let updated = device.item("fixture-mail".into()).unwrap();
    assert_eq!(updated.username, "owner@example.test");
    assert!(matches!(
        device.update_saved(
            mail.clone(),
            "fixture-mail".into(),
            mail_item.revision,
            String::new(),
            "again".into()
        ),
        Err(MobileError::ChangedElsewhere)
    ));
    assert!(matches!(
        device.update_saved(
            mail.clone(),
            "fixture-mail".into(),
            updated.revision.clone(),
            String::new(),
            "".into()
        ),
        Err(MobileError::InvalidItem { .. })
    ));
    let shared = device.item("fixture-shared".into()).unwrap();
    assert!(matches!(
        device.update_saved(
            chat.clone(),
            "fixture-shared".into(),
            shared.revision,
            String::new(),
            "x".into()
        ),
        Err(MobileError::InConflict)
    ));
}

#[test]
fn a_new_login_is_saved_for_the_page_or_the_app_that_asked() {
    let (_dir, folder, device) = device();
    let shop = page(&["https://shop.example.org:8443", "https://example.org"]);
    let id = device
        .save_new(
            shop.clone(),
            " Shop ".into(),
            "buyer".into(),
            "made up".into(),
        )
        .unwrap();
    let saved = device.item(id.clone()).unwrap();
    assert_eq!(
        (
            saved.title.as_str(),
            saved.url.as_str(),
            saved.username.as_str()
        ),
        ("Shop", "https://shop.example.org:8443", "buyer")
    );
    assert_eq!(device.password(id.clone()).unwrap(), "made up");
    assert!(device
        .fill(page(&["https://shop.example.org:8443"]), id, Asks::Login)
        .is_ok());

    let chat = app("org.example.chat:AB12");
    let id = device
        .save_new(
            chat.clone(),
            "Chat".into(),
            "me".into(),
            "chat password".into(),
        )
        .unwrap();
    assert_eq!(device.item(id.clone()).unwrap().url, "");
    assert!(device.fill(chat.clone(), id, Asks::Login).is_ok());
    assert_eq!(offered(&device, chat, Asks::Login).0, ["Chat"]);

    let id = device
        .save_new(
            Requester::Unnamed,
            "Somewhere".into(),
            "me".into(),
            "x".into(),
        )
        .unwrap();
    assert_eq!(device.item(id).unwrap().url, "");
    let kept: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("app-logins.json")).unwrap()).unwrap();
    assert_eq!(kept.as_object().unwrap().len(), 1);
}

#[test]
fn the_choices_an_earlier_build_kept_are_added_to_those_here_once() {
    let (_dir, folder, device) = device();
    let chat = app("org.example.chat:AB12");
    device
        .fill_chosen(chat.clone(), "fixture-mail".into(), Asks::Login)
        .unwrap();
    let earlier = HashMap::from([
        (
            "org.example.chat:AB12".to_owned(),
            vec!["fixture-bank".to_owned()],
        ),
        (
            "org.example.mail:CD34:mail.example.test".to_owned(),
            vec!["fixture-mail".to_owned(), "gone".to_owned()],
        ),
        (String::new(), vec!["fixture-bank".to_owned()]),
    ]);
    device.import_app_choices(earlier.clone()).unwrap();
    let file = std::fs::read(folder.join("app-logins.json")).unwrap();
    // Again, it changes nothing.
    device.import_app_choices(earlier).unwrap();
    assert_eq!(std::fs::read(folder.join("app-logins.json")).unwrap(), file);
    assert_eq!(offered(&device, chat, Asks::Login).0, ["Bank", "Mail"]);
    // An ID no longer in the vault is passed over.
    assert_eq!(
        offered(
            &device,
            app("org.example.mail:CD34:mail.example.test"),
            Asks::Login
        )
        .0,
        ["Mail"]
    );
    let kept: serde_json::Value = serde_json::from_slice(&file).unwrap();
    assert_eq!(kept.as_object().unwrap().len(), 2);

    // A file not of that form is taken for none, and replaced by the next
    // choice.
    std::fs::write(folder.join("app-logins.json"), b"not json").unwrap();
    let chat = app("org.example.chat:AB12");
    assert_eq!(
        offered(&device, chat.clone(), Asks::Login),
        (vec![], vec![])
    );
    device
        .fill_chosen(chat.clone(), "fixture-mail".into(), Asks::Login)
        .unwrap();
    assert_eq!(offered(&device, chat, Asks::Login).0, ["Mail"]);
}
