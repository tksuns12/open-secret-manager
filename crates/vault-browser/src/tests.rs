//! The desk served over a real socket (on Windows, a real named pipe) in one
//! process, with real vaults.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use osm_browser_link::{
    endpoint,
    frame::{self, Prefix, MAX_FRAME},
    Caller, CardField, CardFrame, CardRequest, Ceremony, FillRequest, Forwarded, ForwardedCard,
    ForwardedPasskey, PasskeyRequest, Refusal, Response, CARD_VERSION, CHROMIUM_EXTENSION_ID,
    PASSKEY_VERSION, VERSION,
};
use osm_vault_core::{Item, ItemKind, Vault};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

use crate::{bind, serve, Choices, Config, Desk, Refused};

const PASSWORD: &str = "correct horse battery staple";
const PATIENCE: Duration = Duration::from_secs(20);

/// A folder with a path short enough for a socket.
#[cfg(unix)]
fn folder() -> TempDir {
    tempfile::Builder::new()
        .prefix("osm")
        .tempdir_in("/tmp")
        .unwrap()
}

#[cfg(windows)]
fn folder() -> TempDir {
    tempfile::Builder::new().prefix("osm").tempdir().unwrap()
}

/// The host's end of a connection, as the platform has it.
#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Connects to the session whose socket, or file naming its pipe, is
/// `path`, once it is there to connect to.
#[cfg(unix)]
async fn connect_to(path: &Path) -> Stream {
    Stream::connect(path).await.unwrap()
}

#[cfg(windows)]
async fn connect_to(path: &Path) -> Stream {
    use tokio::net::windows::named_pipe::ClientOptions;

    timeout(PATIENCE, async {
        loop {
            // The file appears once the pipe exists; a pipe whose instance
            // is taken is free again in a moment.
            if let Ok(link) = endpoint::read_link(path) {
                match ClientOptions::new().open(&link.name) {
                    Ok(mut client) => {
                        osm_browser_link::handshake::as_host(&mut client, &link.name, &link.secret)
                            .await
                            .expect("the session proves it holds the secret");
                        return client;
                    }
                    Err(error) if error.raw_os_error() == Some(231) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("{error}"),
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the session's pipe is there")
}

/// A running session: a desk served on a socket.
struct Session {
    dir: TempDir,
    desk: Arc<Desk>,
    serving: JoinHandle<std::io::Result<()>>,
}

impl Session {
    fn start(config: Config) -> Self {
        let dir = folder();
        let desk = Desk::new(config);
        let bound = bind(&endpoint::socket_in(dir.path())).unwrap();
        let serving = tokio::spawn(serve(bound, desk.clone()));
        Self { dir, desk, serving }
    }

    fn socket(&self) -> PathBuf {
        endpoint::socket_in(self.dir.path())
    }

    /// The request the owner is asked about, once there is one.
    async fn asked(&self, vault: Option<&Vault>) -> Choices {
        let mut changes = self.desk.changes();
        timeout(PATIENCE, async {
            loop {
                if let Some(choices) = self.desk.choices(vault).unwrap() {
                    return choices;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .expect("a request arrives")
    }

    /// Waits until no request is waiting.
    async fn idle(&self) {
        let mut changes = self.desk.changes();
        timeout(PATIENCE, async {
            while self.desk.choices(None).unwrap().is_some() {
                changes.changed().await.unwrap();
            }
        })
        .await
        .expect("the request ends")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// The host's end of one connection.
struct Client(Stream);

impl Client {
    async fn connect(session: &Session) -> Self {
        Self(connect_to(&session.socket()).await)
    }

    /// Connects and brings one request.
    async fn bring(session: &Session, forwarded: &Forwarded) -> Self {
        let mut client = Self::connect(session).await;
        let body = frame::encode(forwarded).unwrap();
        client.send(&Prefix::Socket.frame(&body).unwrap()).await;
        client
    }

    /// Connects and brings one passkey's request.
    async fn bring_passkey(session: &Session, forwarded: &ForwardedPasskey) -> Self {
        let mut client = Self::connect(session).await;
        let body = frame::encode(forwarded).unwrap();
        client.send(&Prefix::Socket.frame(&body).unwrap()).await;
        client
    }

    /// Connects and brings one card's request.
    async fn bring_card(session: &Session, forwarded: &ForwardedCard) -> Self {
        let mut client = Self::connect(session).await;
        let body = frame::encode(forwarded).unwrap();
        client.send(&Prefix::Socket.frame(&body).unwrap()).await;
        client
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).await.unwrap();
    }

    /// The next response, or `None` once the session closed the connection.
    async fn next(&mut self) -> Option<Response> {
        timeout(PATIENCE, async {
            let mut prefix = [0_u8; 4];
            match self.0.read_exact(&mut prefix).await {
                Ok(_) => {}
                Err(_) => return None,
            }
            let mut body = vec![0_u8; Prefix::Socket.length(prefix).unwrap()];
            self.0.read_exact(&mut body).await.unwrap();
            Some(serde_json::from_slice(&body).unwrap())
        })
        .await
        .expect("the session answers or closes")
    }

    /// The response that ends the request, after any number of reminders.
    async fn last(&mut self) -> Option<Response> {
        loop {
            match self.next().await {
                Some(Response::Waiting(_)) => {}
                other => return other,
            }
        }
    }

    /// Asserts that nothing arrives for a while.
    async fn is_quiet(&mut self) {
        let mut byte = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(150), self.0.read(&mut byte))
                .await
                .is_err(),
            "the session said something"
        );
    }
}

fn extension() -> Caller {
    Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/"))
}

fn request(id: &str, origin: &str) -> FillRequest {
    FillRequest {
        version: VERSION,
        request_id: id.into(),
        tab_id: 31,
        frame_id: 0,
        document_id: format!("document-of-{id}"),
        origin: origin.into(),
    }
}

fn fill(id: &str, origin: &str) -> Forwarded {
    Forwarded {
        caller: extension(),
        request: request(id, origin),
    }
}

fn waiting(id: &str) -> Option<Response> {
    Some(Response::Waiting(osm_browser_link::Waiting {
        request_id: id.into(),
    }))
}

fn refusal(id: &str, code: Refusal) -> Option<Response> {
    Some(Response::refusal(id, code))
}

fn login(title: &str, address: &str) -> Item {
    let mut item = Item::new(title);
    item.username = format!("{title}@example.test");
    item.password = format!("{title} password");
    item.url = address.into();
    item
}

/// A vault holding `items`, unlocked.
fn vault_with(dir: &Path, items: &[Item]) -> Vault {
    let (mut vault, _) = Vault::create(dir.join("vault.sqlite3"), PASSWORD).unwrap();
    for item in items {
        vault.put(item.clone()).unwrap();
    }
    vault
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owners_choice_fills_the_one_request_it_was_made_for() {
    let session = Session::start(Config::default());
    let exact = login("exact", "https://example.com/login");
    let port = login("port", "https://example.com:8443/login");
    let subdomain = login("subdomain", "https://www.example.com/");
    let plain = login("plain", "http://example.com/");
    let vault = vault_with(session.dir.path(), &[exact.clone(), port, subdomain, plain]);

    let asked = fill("first", "https://example.com");
    let mut client = Client::bring(&session, &asked).await;
    // The session says at once that it has the request.
    assert_eq!(client.next().await, waiting("first"));

    let choices = session.asked(Some(&vault)).await;
    assert_eq!(choices.request_id, "first");
    assert_eq!(choices.origin, "https://example.com");
    assert_eq!(choices.browser, "Chromium");
    assert!(choices.seconds_left > 100 && choices.seconds_left <= 120);
    assert_eq!(choices.session, vault.unlock_session());
    // Only the login stored for exactly that origin is offered.
    let offered: Vec<&str> = choices.logins.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(offered, [exact.id.as_str()]);
    // Nothing is sent until the owner chooses.
    client.is_quiet().await;

    session
        .desk
        .approve("first", &exact.id, choices.session.unwrap(), &vault)
        .unwrap();
    let Some(Response::FillReply(reply)) = client.next().await else {
        panic!("a reply")
    };
    assert!(reply.answers(&asked.request));
    assert_eq!(reply.username, "exact@example.test");
    assert_eq!(reply.password, "exact password");
    // That was all: the connection closes and nothing waits.
    assert_eq!(client.next().await, None);
    assert!(session.desk.choices(Some(&vault)).unwrap().is_none());

    // The choice was for that one request and is spent.
    assert!(matches!(
        session
            .desk
            .approve("first", &exact.id, choices.session.unwrap(), &vault),
        Err(Refused::NotPending)
    ));
    assert!(!session.desk.deny("first"));
    // The same request again is refused, whoever brings it.
    let mut replay = Client::bring(&session, &asked).await;
    assert_eq!(replay.next().await, refusal("first", Refusal::Replayed));
    assert_eq!(replay.next().await, None);
    assert!(session.desk.choices(Some(&vault)).unwrap().is_none());
}

/// A card's request from a checkout page whose number and code are in a
/// payment provider's frame.
fn card_request(id: &str, code: bool) -> ForwardedCard {
    let mut payment = vec![CardField::Number];
    if code {
        payment.push(CardField::SecurityCode);
    }
    ForwardedCard {
        caller: extension(),
        card: CardRequest {
            version: CARD_VERSION,
            request_id: id.into(),
            tab_id: 31,
            top_origin: "https://shop.example".into(),
            frames: vec![
                CardFrame {
                    frame_id: 0,
                    document_id: format!("page-of-{id}"),
                    origin: "https://shop.example".into(),
                    fields: vec![CardField::Cardholder, CardField::Expiry],
                },
                CardFrame {
                    frame_id: 2,
                    document_id: format!("frame-of-{id}"),
                    origin: "https://pay.example.net".into(),
                    fields: payment,
                },
            ],
        },
    }
}

fn card(title: &str) -> Item {
    let mut item = Item::new(title);
    item.kind = ItemKind::Card;
    osm_vault_core::card::CardChange {
        cardholder: Some("Owner".into()),
        number: Some("4111 1111 1111 1111".into()),
        expiry_month: Some("3".into()),
        expiry_year: Some("2030".into()),
        security_code: Some("123".into()),
        brand: None,
    }
    .apply_to(&mut item);
    item
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_card_goes_to_a_card_request_with_only_the_fields_it_asks_for() {
    let session = Session::start(Config::default());
    let visa = card("Visa");
    let bank = login("bank", "https://shop.example/");
    let mut vault = vault_with(session.dir.path(), &[visa.clone(), bank.clone()]);

    let asked = card_request("card", true);
    let mut client = Client::bring_card(&session, &asked).await;
    assert_eq!(client.next().await, waiting("card"));
    let choices = session.asked(Some(&vault)).await;
    assert_eq!(choices.origin, "https://shop.example");
    assert!(choices.logins.is_empty());
    let card_choices = choices.card.clone().unwrap();
    // Every card, for any page; each document named with its origin.
    let offered: Vec<&str> = card_choices
        .cards
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(offered, [visa.id.as_str()]);
    assert_eq!(card_choices.frames, asked.card.frames);
    client.is_quiet().await;

    // A card is not a login, nor a login a card.
    let unlock = choices.session.unwrap();
    assert!(matches!(
        session.desk.approve("card", &visa.id, unlock, &vault),
        Err(Refused::NotForThisPage)
    ));
    assert!(matches!(
        session.desk.approve_card("card", &bank.id, unlock, &vault),
        Err(Refused::NotForThisPage)
    ));
    session
        .desk
        .approve_card("card", &visa.id, unlock, &vault)
        .unwrap();
    let Some(Response::CardReply(reply)) = client.next().await else {
        panic!("a reply")
    };
    assert!(reply.answers(&asked.card));
    let values = &reply.card;
    assert_eq!(
        (
            values.cardholder.as_str(),
            values.number.as_str(),
            values.expiry_month.as_str(),
            values.expiry_year.as_str(),
            values.security_code.as_str()
        ),
        ("Owner", "4111111111111111", "03", "2030", "123")
    );
    assert_eq!(client.next().await, None);

    // A request that does not ask for the code is not given it.
    let asked = card_request("no-code", false);
    let mut client = Client::bring_card(&session, &asked).await;
    let choices = session.asked(Some(&vault)).await;
    session
        .desk
        .approve_card("no-code", &visa.id, choices.session.unwrap(), &vault)
        .unwrap();
    let Some(Response::CardReply(reply)) = client.last().await else {
        panic!("a reply")
    };
    assert_eq!(reply.card.security_code, "");
    assert_eq!(reply.card.number, "4111111111111111");

    // Locked, no card is listed, and none is released.
    let asked = card_request("locked", true);
    let mut client = Client::bring_card(&session, &asked).await;
    let choices = session.asked(Some(&vault)).await;
    let unlock = choices.session.unwrap();
    vault.lock();
    let choices = session.desk.choices(Some(&vault)).unwrap().unwrap();
    assert!(choices.card.unwrap().cards.is_empty() && choices.session.is_none());
    assert!(matches!(
        session
            .desk
            .approve_card("locked", &visa.id, unlock, &vault),
        Err(Refused::Locked)
    ));
    assert!(session.desk.deny("locked"));
    assert_eq!(client.last().await, refusal("locked", Refusal::Denied));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_login_for_the_pages_origin_can_be_chosen() {
    let session = Session::start(Config::default());
    let mut note = login("note", "https://example.com/");
    note.kind = ItemKind::SecureNote;
    let others = [
        login("port", "https://example.com:8443/"),
        login("subdomain", "https://login.example.com/"),
        login("parent", "https://com/"),
        login("plain", "http://example.com/"),
        login("lookalike", "https://example.com.evil.test/"),
        note,
    ];
    let vault = vault_with(session.dir.path(), &others);

    let mut client = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(client.next().await, waiting("first"));
    let choices = session.asked(Some(&vault)).await;
    assert!(choices.logins.is_empty());
    let unlock = choices.session.unwrap();

    // Naming an item the owner was not offered releases nothing, and the
    // request keeps waiting.
    for item in &others {
        assert!(
            matches!(
                session.desk.approve("first", &item.id, unlock, &vault),
                Err(Refused::NotForThisPage)
            ),
            "{}",
            item.title
        );
    }
    assert!(matches!(
        session
            .desk
            .approve("first", "no-such-item", unlock, &vault),
        Err(Refused::NotForThisPage)
    ));
    // Nor does a choice for a request that is not the waiting one.
    assert!(matches!(
        session
            .desk
            .approve("second", &others[0].id, unlock, &vault),
        Err(Refused::NotPending)
    ));
    client.is_quiet().await;
    assert_eq!(session.asked(Some(&vault)).await.request_id, "first");

    // The owner turns it down.
    assert!(session.desk.deny("first"));
    assert_eq!(client.next().await, refusal("first", Refusal::Denied));
    assert_eq!(client.next().await, None);
    assert!(!session.desk.deny("first"));

    // On the other port, the login stored for that port is the one offered.
    let mut client = Client::bring(&session, &fill("second", "https://example.com:8443")).await;
    assert_eq!(client.next().await, waiting("second"));
    let choices = session.asked(Some(&vault)).await;
    assert_eq!(choices.logins.len(), 1);
    assert_eq!(choices.logins[0].id, others[0].id);
    session
        .desk
        .approve("second", &others[0].id, unlock, &vault)
        .unwrap();
    let Some(Response::FillReply(reply)) = client.next().await else {
        panic!("a reply")
    };
    assert_eq!(reply.origin, "https://example.com:8443");
    assert_eq!(reply.username, "port@example.test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_waits_for_the_unlock_and_a_lock_ends_the_owners_choice() {
    let session = Session::start(Config::default());
    let exact = login("exact", "https://example.com/");
    let mut vault = vault_with(session.dir.path(), std::slice::from_ref(&exact));
    vault.lock();

    // The request arrives while the vault is locked. It waits, and shows
    // no login.
    let mut client = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(client.next().await, waiting("first"));
    let locked = session.asked(Some(&vault)).await;
    assert_eq!((locked.session, locked.logins.len()), (None, 0));
    let without_vault = session.asked(None).await;
    assert_eq!(
        (without_vault.session, without_vault.logins.len()),
        (None, 0)
    );
    assert_eq!(without_vault.request_id, "first");

    vault.unlock(PASSWORD).unwrap();
    let choices = session.asked(Some(&vault)).await;
    let first_unlock = choices.session.unwrap();
    assert_eq!(choices.logins.len(), 1);

    // The vault locks before the owner's choice takes effect: nothing is
    // released, and the request keeps waiting.
    vault.lock();
    assert!(matches!(
        session
            .desk
            .approve("first", &exact.id, first_unlock, &vault),
        Err(Refused::Locked)
    ));
    // Unlocking again does not bring the earlier choice back.
    vault.unlock(PASSWORD).unwrap();
    assert!(matches!(
        session
            .desk
            .approve("first", &exact.id, first_unlock, &vault),
        Err(Refused::Locked)
    ));
    client.is_quiet().await;

    // A choice made under the new unlock does.
    let choices = session.asked(Some(&vault)).await;
    let second_unlock = choices.session.unwrap();
    assert_ne!(second_unlock, first_unlock);
    session
        .desk
        .approve("first", &exact.id, second_unlock, &vault)
        .unwrap();
    let Some(Response::FillReply(reply)) = client.next().await else {
        panic!("a reply")
    };
    assert_eq!(reply.password, "exact password");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_request_gets_nothing_even_if_the_owner_then_chooses() {
    let session = Session::start(Config::default());
    let exact = login("exact", "https://example.com/");
    let vault = vault_with(session.dir.path(), std::slice::from_ref(&exact));

    let mut client = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(client.next().await, waiting("first"));
    let choices = session.asked(Some(&vault)).await;

    // The page went away: the host closes the connection.
    drop(client);
    session.idle().await;
    assert!(matches!(
        session
            .desk
            .approve("first", &exact.id, choices.session.unwrap(), &vault),
        Err(Refused::NotPending)
    ));
    assert!(!session.desk.deny("first"));

    // The next request is taken, and the withdrawn one stays spent.
    let mut again = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(again.next().await, refusal("first", Refusal::Replayed));
    let mut next = Client::bring(&session, &fill("second", "https://example.com")).await;
    assert_eq!(next.next().await, waiting("second"));
    assert_eq!(session.asked(None).await.request_id, "second");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_ends_when_the_owner_does_not_decide_in_time() {
    let session = Session::start(Config {
        decide_within: Duration::from_millis(600),
        remind_every: Duration::from_millis(100),
        ..Config::default()
    });
    let mut client = Client::bring(&session, &fill("first", "https://example.com")).await;
    // While the owner has not decided, the extension is told so again and
    // again.
    for _ in 0..3 {
        assert_eq!(client.next().await, waiting("first"));
    }
    assert_eq!(session.asked(None).await.request_id, "first");
    assert_eq!(client.last().await, refusal("first", Refusal::Expired));
    assert_eq!(client.next().await, None);
    assert!(session.desk.choices(None).unwrap().is_none());
    assert!(!session.desk.deny("first"));

    // It no longer holds the next one back.
    let mut next = Client::bring(&session, &fill("second", "https://example.com")).await;
    assert_eq!(next.next().await, waiting("second"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_request_waits_at_a_time() {
    let session = Session::start(Config::default());
    let mut first = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(first.next().await, waiting("first"));

    let mut second = Client::bring(&session, &fill("second", "https://other.test")).await;
    assert_eq!(second.next().await, refusal("second", Refusal::Busy));
    assert_eq!(second.next().await, None);
    let mut same = Client::bring(&session, &fill("first", "https://example.com")).await;
    assert_eq!(same.next().await, refusal("first", Refusal::Replayed));

    // The first is still the one the owner is asked about.
    let asked = session.asked(None).await;
    assert_eq!(
        (asked.request_id.as_str(), asked.origin.as_str()),
        ("first", "https://example.com")
    );
    first.is_quiet().await;
    assert!(session.desk.deny("first"));
    assert_eq!(first.next().await, refusal("first", Refusal::Denied));

    // The one turned away as busy may be made again.
    let mut second = Client::bring(&session, &fill("second", "https://other.test")).await;
    assert_eq!(second.next().await, waiting("second"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_host_would_not_send_is_refused_or_ignored() {
    let session = Session::start(Config {
        exchange_within: Duration::from_millis(300),
        ..Config::default()
    });
    let refused = |forwarded: Forwarded| {
        let session = &session;
        async move {
            let mut client = Client::bring(session, &forwarded).await;
            let answer = client.next().await;
            assert_eq!(client.next().await, None);
            answer
        }
    };

    let mut forged = fill("a", "https://example.com");
    forged.caller = Caller::Chromium("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into());
    assert_eq!(
        refused(forged).await,
        refusal("a", Refusal::ExtensionNotAllowed)
    );
    assert_eq!(
        refused(fill("a", "http://example.com")).await,
        refusal("a", Refusal::OriginRejected)
    );
    assert_eq!(
        refused(fill("a", "https://example.com/")).await,
        refusal("a", Refusal::OriginRejected)
    );
    let mut framed = fill("a", "https://example.com");
    framed.request.frame_id = 2;
    assert_eq!(refused(framed).await, refusal("a", Refusal::FrameRejected));
    let mut versioned = fill("a", "https://example.com");
    versioned.request.version = 2;
    assert_eq!(
        refused(versioned).await,
        refusal("a", Refusal::UnsupportedVersion)
    );
    // An ID that is not a plain one is not repeated back.
    assert_eq!(
        refused(fill("<a>", "https://example.com")).await,
        Some(Response::Error(osm_browser_link::Failure::unnamed(
            Refusal::InvalidMessage
        )))
    );

    // What is not a request at all is closed without an answer.
    let frame_of = |body: &[u8]| -> Vec<u8> { Prefix::Socket.frame(body).unwrap().to_vec() };
    let too_long = ((MAX_FRAME + 1) as u32).to_be_bytes();
    for bytes in [
        frame_of(b"not json"),
        frame_of(b"{}"),
        frame_of(br#"{"type":"fill_request","version":1}"#),
        too_long.to_vec(),
        vec![0, 0, 0, 0],
        // Half a frame, and then nothing.
        vec![0, 0, 0, 40, b'{'],
        // Nothing at all.
        Vec::new(),
    ] {
        let mut client = Client::connect(&session).await;
        client.send(&bytes).await;
        assert_eq!(client.next().await, None, "{bytes:?}");
    }
    assert!(session.desk.choices(None).unwrap().is_none());

    // A connection that says more after its request is not the host: its
    // request is withdrawn.
    let mut chatty = Client::bring(&session, &fill("b", "https://example.com")).await;
    assert_eq!(chatty.next().await, waiting("b"));
    assert_eq!(session.asked(None).await.request_id, "b");
    chatty.send(&frame_of(br#"{"type":"approve"}"#)).await;
    assert_eq!(chatty.last().await, None);
    session.idle().await;

    // None of the refused requests spent the ID "a".
    let mut client = Client::bring(&session, &fill("a", "https://example.com")).await;
    assert_eq!(client.next().await, waiting("a"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(unix)]
async fn one_session_listens_on_a_socket_and_cleans_up_after_itself() {
    use std::os::unix::fs::PermissionsExt;

    let dir = folder();
    let path = endpoint::socket_in(&dir.path().join("made").join("on").join("demand"));
    let desk = Desk::new(Config::default());
    let bound = bind(&path).unwrap();
    assert_eq!(bound.path(), path);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // A second session is refused while the first one listens.
    let serving = tokio::spawn(serve(bound, desk.clone()));
    let in_use = bind(&path).err().unwrap();
    assert_eq!(in_use.kind(), std::io::ErrorKind::AddrInUse);
    // The refusal did not disturb the first.
    let mut client = Client(connect_to(&path).await);
    let body = frame::encode(&fill("first", "https://example.com")).unwrap();
    client.send(&Prefix::Socket.frame(&body).unwrap()).await;
    assert_eq!(client.next().await, waiting("first"));

    // When the session stops, the socket goes with it, and the request
    // gets no answer.
    serving.abort();
    assert_eq!(client.last().await, None);
    timeout(PATIENCE, async {
        while path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the socket is removed");
    assert!(endpoint::connect(&path).is_err());

    // A socket left behind by a session that died is replaced.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let bound = bind(&path).unwrap();
    drop(bound);
    assert!(!path.exists());

    // Anything else in the socket's place is left as it is.
    std::fs::write(&path, b"not a socket").unwrap();
    assert_eq!(
        bind(&path).err().unwrap().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(windows)]
async fn one_session_listens_on_a_pipe_and_cleans_up_after_itself() {
    let dir = folder();
    let path = endpoint::pipe_file_in(&dir.path().join("made").join("on").join("demand"));
    let desk = Desk::new(Config::default());
    let bound = bind(&path).unwrap();
    assert_eq!(bound.path(), path);
    assert!(endpoint::is_pipe_name(bound.name()));
    // Nothing names the pipe until it exists.
    assert!(!path.exists());

    let serving = tokio::spawn(serve(bound, desk.clone()));
    let mut client = Client(connect_to(&path).await);
    // A second session is refused while the first one listens.
    assert_eq!(
        bind(&path).err().unwrap().kind(),
        std::io::ErrorKind::AddrInUse
    );
    // The refusal did not disturb the first.
    let body = frame::encode(&fill("first", "https://example.com")).unwrap();
    client.send(&Prefix::Socket.frame(&body).unwrap()).await;
    assert_eq!(client.next().await, waiting("first"));

    // Nobody can make the pipe first, even knowing its name.
    let link = endpoint::read_link(&path).unwrap();
    let taken = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&link.name);
    assert!(taken.is_err());

    // A host that does not hold the secret is closed on, and its bytes are
    // not taken for a request.
    let mut stranger = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&link.name)
        .unwrap();
    let wrong = osm_browser_link::handshake::new_secret().unwrap();
    assert!(
        osm_browser_link::handshake::as_host(&mut stranger, &link.name, &wrong)
            .await
            .is_err()
    );
    // And the session is still serving: a host that holds the secret gets
    // in (connecting is proving it).
    let _again = connect_to(&path).await;

    // When the session stops, the file goes with it, and the request gets
    // no answer.
    serving.abort();
    assert_eq!(client.last().await, None);
    timeout(PATIENCE, async {
        while path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the file is removed");

    // A file that names a pipe nobody listens on is replaced.
    let stale = endpoint::Link::new().unwrap();
    stale.write(&path).unwrap();
    let bound = bind(&path).unwrap();
    // Not the stale name: the next session chooses its own, and writes it
    // when it serves.
    assert_ne!(bound.name(), stale.name);
}

/// What a session that was killed leaves: a file naming its pipe, which
/// somebody else can then make. The next session starts regardless, and the
/// host sends nothing to the impostor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(windows)]
async fn a_pipe_made_by_someone_else_under_a_left_over_name_is_not_a_session() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ServerOptions,
    };

    let dir = folder();
    let path = endpoint::pipe_file_in(dir.path());
    let left = endpoint::Link::new().unwrap();
    left.write(&path).unwrap();
    // The impostor listens under the name and answers like a session that
    // does not know the secret.
    let impostor = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&left.name)
        .unwrap();
    // Whatever any connection sends it after the host's number.
    let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listening = tokio::spawn({
        let (name, heard, connections) = (left.name.clone(), heard.clone(), connections.clone());
        async move {
            let mut impostor = impostor;
            loop {
                impostor.connect().await.unwrap();
                let next = ServerOptions::new().create(&name).unwrap();
                let mut connection = std::mem::replace(&mut impostor, next);
                let mut number = [0_u8; 32];
                if connection.read_exact(&mut number).await.is_err() {
                    continue;
                }
                connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = connection.write_all(&[9_u8; 64]).await;
                let mut rest = Vec::new();
                let _ = connection.read_to_end(&mut rest).await;
                heard.lock().unwrap().extend(rest);
            }
        }
    });

    // The next session is not told another one is listening.
    let bound = bind(&path).expect("the file's pipe is not a session");
    assert_ne!(bound.name(), left.name);

    // And a host that follows the file it had read earlier gets nowhere.
    let mut host = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&left.name)
        .unwrap();
    assert!(
        osm_browser_link::handshake::as_host(&mut host, &left.name, &left.secret)
            .await
            .is_err()
    );
    drop(host);
    tokio::time::sleep(Duration::from_millis(300)).await;
    listening.abort();
    // The impostor was really reached, by the probe and by the host, and
    // was sent a number each time and nothing after it.
    assert!(connections.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    assert!(heard.lock().unwrap().is_empty());
}

/// A page's request for a passkey: to make one for `example.com`, from a
/// page of `https://login.example.com`, or to sign in.
fn passkey_request(
    id: &str,
    ceremony: Ceremony,
    change: impl FnOnce(&mut serde_json::Value),
) -> ForwardedPasskey {
    let mut options = match ceremony {
        Ceremony::Create => serde_json::json!({
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": "AQIDBA", "name": "owner@example.com", "displayName": "Owner" },
            "challenge": "Y2hhbGxlbmdlIG9mIGEgc2l0ZQ",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "residentKey": "required", "userVerification": "preferred" },
        }),
        Ceremony::Get => serde_json::json!({
            "challenge": "c2lnbi1pbi1jaGFsbGVuZ2U",
            "rpId": "example.com",
            "userVerification": "preferred",
        }),
    };
    change(&mut options);
    ForwardedPasskey {
        caller: extension(),
        ceremony,
        passkey: PasskeyRequest {
            version: PASSKEY_VERSION,
            request_id: id.into(),
            tab_id: 31,
            origin: "https://login.example.com".into(),
            options: options.to_string(),
        },
    }
}

/// What a passkey's reply carries, read, with its client data.
fn credential_of(
    reply: Option<Response>,
    request: &ForwardedPasskey,
) -> (serde_json::Value, serde_json::Value) {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let Some(Response::PasskeyReply(reply)) = reply else {
        panic!("a passkey's reply: {reply:?}")
    };
    assert!(reply.answers(&request.passkey));
    let credential: serde_json::Value = serde_json::from_str(&reply.credential).unwrap();
    let data =
        Base64UrlUnpadded::decode_vec(credential["response"]["clientDataJSON"].as_str().unwrap())
            .unwrap();
    (credential, serde_json::from_slice(&data).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pages_passkey_is_made_and_signed_in_with_once_the_owner_chooses() {
    use osm_vault_core::passkey::UserVerification;
    let session = Session::start(Config::default());
    let on_site = login("on site", "https://example.com/");
    let elsewhere = login("elsewhere", "https://example.org/");
    let mut vault = vault_with(session.dir.path(), &[on_site.clone(), elsewhere]);

    let create = passkey_request("make", Ceremony::Create, |_| {});
    let mut client = Client::bring_passkey(&session, &create).await;
    assert_eq!(client.next().await, waiting("make"));
    let choices = session.asked(Some(&vault)).await;
    let asked = choices.passkey.clone().unwrap();
    assert_eq!(
        (
            asked.ceremony,
            asked.rp_id.as_str(),
            asked.rp_name.as_str(),
            asked.user_name.as_str()
        ),
        (
            Ceremony::Create,
            "example.com",
            "Example",
            "owner@example.com"
        )
    );
    assert_eq!(asked.verification, UserVerification::Preferred);
    assert_eq!(
        asked
            .logins
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        [on_site.id.as_str()]
    );
    assert!(choices.logins.is_empty() && choices.card.is_none());
    // Not a login's or a card's to answer.
    let unlock = choices.session.unwrap();
    assert!(matches!(
        session.desk.approve("make", &on_site.id, unlock, &vault),
        Err(Refused::NotForThisPage)
    ));
    client.is_quiet().await;

    session
        .desk
        .approve_passkey_create("make", unlock, &mut vault, None, true)
        .unwrap();
    let (made, client_data) = credential_of(client.next().await, &create);
    // The client data is the page's own, as a browser would make it.
    assert_eq!(client_data["type"], "webauthn.create");
    assert_eq!(client_data["origin"], "https://login.example.com");
    assert_eq!(client_data["challenge"], "Y2hhbGxlbmdlIG9mIGEgc2l0ZQ");
    assert_eq!(client_data["crossOrigin"], false);
    assert_eq!(made["response"]["publicKeyAlgorithm"], -7);
    assert_eq!(client.next().await, None);
    let saved = vault
        .list()
        .unwrap()
        .into_iter()
        .find(|item| item.passkeys == 1)
        .unwrap();
    assert_eq!(
        (saved.title.as_str(), saved.username.as_str()),
        ("example.com", "owner@example.com")
    );

    // Signed in with: only a passkey the site takes, and once.
    let get = passkey_request("sign", Ceremony::Get, |_| {});
    let mut client = Client::bring_passkey(&session, &get).await;
    assert_eq!(client.next().await, waiting("sign"));
    let choices = session.asked(Some(&vault)).await;
    let asked = choices.passkey.clone().unwrap();
    assert_eq!(asked.passkeys.len(), 1);
    let credential = asked.passkeys[0].passkey.credential_id.clone();
    assert_eq!(credential, made["id"].as_str().unwrap());
    let unlock = choices.session.unwrap();
    assert!(matches!(
        session
            .desk
            .approve_passkey_get("sign", unlock, &vault, &on_site.id, &credential, true),
        Err(Refused::NotForThisPage)
    ));
    session
        .desk
        .approve_passkey_get("sign", unlock, &vault, &saved.id, &credential, true)
        .unwrap();
    let (signed, client_data) = credential_of(client.next().await, &get);
    assert_eq!(client_data["type"], "webauthn.get");
    assert_eq!(client_data["origin"], "https://login.example.com");
    assert_eq!(signed["id"], made["id"]);
    assert_eq!(signed["response"]["userHandle"], "AQIDBA");
    assert!(matches!(
        session
            .desk
            .approve_passkey_get("sign", unlock, &vault, &saved.id, &credential, true),
        Err(Refused::NotPending)
    ));

    // The site has it already: once the owner chooses to save another, the
    // page is told so, and nothing is made.
    let again = passkey_request("again", Ceremony::Create, |options| {
        options["excludeCredentials"] =
            serde_json::json!([{ "type": "public-key", "id": credential }]);
    });
    let mut client = Client::bring_passkey(&session, &again).await;
    assert_eq!(client.next().await, waiting("again"));
    let unlock = session.asked(Some(&vault)).await.session.unwrap();
    assert!(matches!(
        session
            .desk
            .approve_passkey_create("again", unlock, &mut vault, Some(&on_site.id), true),
        Err(Refused::Exists)
    ));
    assert_eq!(
        client.last().await,
        refusal("again", Refusal::PasskeyExists)
    );
    assert_eq!(vault.get(&on_site.id).unwrap().item.passkeys.len(), 0);

    // Added to a login of the site, when the owner says so; a site that
    // requires verification gets nothing without it.
    let required = passkey_request("required", Ceremony::Create, |options| {
        options["authenticatorSelection"]["userVerification"] = serde_json::json!("required");
        options["user"]["id"] = serde_json::json!("BQYHCA");
    });
    let mut client = Client::bring_passkey(&session, &required).await;
    assert_eq!(client.next().await, waiting("required"));
    let unlock = session.asked(Some(&vault)).await.session.unwrap();
    assert!(matches!(
        session.desk.approve_passkey_create(
            "required",
            unlock,
            &mut vault,
            Some(&on_site.id),
            false
        ),
        Err(Refused::NotVerified)
    ));
    session
        .desk
        .approve_passkey_create("required", unlock, &mut vault, Some(&on_site.id), true)
        .unwrap();
    credential_of(client.next().await, &required);
    assert_eq!(vault.get(&on_site.id).unwrap().item.passkeys.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pages_request_is_left_to_the_browser_when_the_app_does_not_answer_it() {
    let session = Session::start(Config::default());
    let mut vault = vault_with(session.dir.path(), &[]);
    // As the app tells the desk: the vault holds no passkey for any site.
    let held = Arc::new(std::sync::Mutex::new(Some(false)));
    let told = held.clone();
    session
        .desk
        .answer_sign_ins_with(Box::new(move |_, _| *told.lock().unwrap()));

    // A sign-in the vault holds nothing for: answered at once, nothing asked.
    let get = passkey_request("none", Ceremony::Get, |_| {});
    let mut client = Client::bring_passkey(&session, &get).await;
    assert_eq!(client.next().await, refusal("none", Refusal::NoPasskey));
    assert!(session.desk.choices(Some(&vault)).unwrap().is_none());
    // While locked the app cannot tell: the owner is asked.
    *held.lock().unwrap() = None;
    let mut client =
        Client::bring_passkey(&session, &passkey_request("locked", Ceremony::Get, |_| {})).await;
    assert_eq!(client.next().await, waiting("locked"));
    // The owner's choice of the browser's own.
    session.asked(Some(&vault)).await;
    assert!(session.desk.use_browser("locked"));
    assert_eq!(client.last().await, refusal("locked", Refusal::UseBrowser));
    assert!(!session.desk.use_browser("locked"));

    // A site no passkey may be for, a page of another site, and one this
    // app reads no key of are refused before anything is asked.
    for (id, change) in [
        (
            "suffix",
            Box::new(|options: &mut serde_json::Value| {
                options["rp"]["id"] = serde_json::json!("com")
            }) as Box<dyn FnOnce(&mut serde_json::Value)>,
        ),
        (
            "other",
            Box::new(|options: &mut serde_json::Value| {
                options["rp"]["id"] = serde_json::json!("example.org")
            }),
        ),
        (
            "key",
            Box::new(|options: &mut serde_json::Value| {
                options["pubKeyCredParams"] =
                    serde_json::json!([{ "type": "public-key", "alg": -257 }])
            }),
        ),
    ] {
        let mut client =
            Client::bring_passkey(&session, &passkey_request(id, Ceremony::Create, change)).await;
        assert_eq!(
            client.next().await,
            refusal(id, Refusal::PasskeyRefused),
            "{id}"
        );
    }

    // A fill the owner starts takes the place of a page's request.
    let mut page =
        Client::bring_passkey(&session, &passkey_request("page", Ceremony::Create, |_| {})).await;
    assert_eq!(page.next().await, waiting("page"));
    let mut owner = Client::bring(&session, &fill("owner", "https://example.com")).await;
    assert_eq!(owner.next().await, waiting("owner"));
    assert_eq!(page.last().await, refusal("page", Refusal::Busy));
    assert_eq!(session.asked(Some(&vault)).await.request_id, "owner");
    // But not the other way round.
    let mut later = Client::bring_passkey(
        &session,
        &passkey_request("later", Ceremony::Create, |_| {}),
    )
    .await;
    assert_eq!(later.next().await, refusal("later", Refusal::Busy));
    assert!(session.desk.deny("owner"));
    assert_eq!(owner.last().await, refusal("owner", Refusal::Denied));

    // A lock ends what the owner chose under it.
    let mut client =
        Client::bring_passkey(&session, &passkey_request("lock", Ceremony::Create, |_| {})).await;
    assert_eq!(client.next().await, waiting("lock"));
    let unlock = session.asked(Some(&vault)).await.session.unwrap();
    vault.lock();
    assert!(session
        .desk
        .choices(Some(&vault))
        .unwrap()
        .unwrap()
        .passkey
        .unwrap()
        .logins
        .is_empty());
    vault.unlock(PASSWORD).unwrap();
    assert!(matches!(
        session
            .desk
            .approve_passkey_create("lock", unlock, &mut vault, None, true),
        Err(Refused::Locked)
    ));
    assert!(vault.list().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkey_sign_in_with_allow_credentials_does_not_probe_holds_and_bound_ticket_rejects_mismatch(
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let session = Session::start(Config::default());
    let mut vault = vault_with(session.dir.path(), &[]);
    let holds_calls = Arc::new(AtomicUsize::new(0));
    let counter = holds_calls.clone();
    session.desk.answer_sign_ins_with(Box::new(move |_, _| {
        counter.fetch_add(1, Ordering::SeqCst);
        Some(false)
    }));

    // 1. Unauthorized caller is rejected before `holds` is consulted.
    let mut forged = passkey_request("forged-caller", Ceremony::Get, |_| {});
    forged.caller = osm_browser_link::Caller::Firefox("evil@example.org".into());
    let mut client = Client::bring_passkey(&session, &forged).await;
    assert_eq!(
        client.next().await,
        refusal("forged-caller", Refusal::ExtensionNotAllowed)
    );
    assert_eq!(holds_calls.load(Ordering::SeqCst), 0);

    // 2. Non-empty `allowCredentials` NEVER triggers silent `NoPasskey` probing.
    let targeted = passkey_request("targeted-allow", Ceremony::Get, |options| {
        options["allowCredentials"] = serde_json::json!([{ "type": "public-key", "id": "AQIDBA" }]);
    });
    let mut client = Client::bring_passkey(&session, &targeted).await;
    assert_eq!(client.next().await, waiting("targeted-allow"));
    assert_eq!(holds_calls.load(Ordering::SeqCst), 0);

    // 3. Bound ticket rejects mismatched ticket / origin / rp_id.
    let (ticket, ceremony, origin, rp_id) = session.desk.pending_passkey("targeted-allow").unwrap();
    assert_eq!(ceremony, Ceremony::Get);
    let unlock = session.asked(Some(&vault)).await.session.unwrap();
    assert!(matches!(
        session.desk.approve_passkey_get_bound(
            ticket + 1,
            "targeted-allow",
            &origin,
            &rp_id,
            unlock,
            &vault,
            "item",
            "cred",
            true,
        ),
        Err(Refused::NotPending)
    ));
    assert!(matches!(
        session.desk.approve_passkey_get_bound(
            ticket,
            "targeted-allow",
            "https://other.example.com",
            &rp_id,
            unlock,
            &vault,
            "item",
            "cred",
            true,
        ),
        Err(Refused::NotPending)
    ));
    assert!(matches!(
        session.desk.approve_passkey_get_bound(
            ticket,
            "targeted-allow",
            &origin,
            "other.example.com",
            unlock,
            &vault,
            "item",
            "cred",
            true,
        ),
        Err(Refused::NotPending)
    ));
    assert!(session.desk.deny("targeted-allow"));
    assert_eq!(
        client.last().await,
        refusal("targeted-allow", Refusal::Denied)
    );

    // 4. Discoverable `no_passkey` fast fallback is rate-limited per origin (3/60s)
    //    and remembers request IDs against replay.
    for index in 0..5 {
        let id = format!("disc-{index}");
        let mut c =
            Client::bring_passkey(&session, &passkey_request(&id, Ceremony::Get, |_| {})).await;
        assert_eq!(c.next().await, refusal(&id, Refusal::NoPasskey));
    }
    // Only the first 3 calls actually queried the vault; subsequent ones were rate-limited.
    assert_eq!(holds_calls.load(Ordering::SeqCst), 3);
    // Replaying a spent `no_passkey` ID is refused as Replayed without consulting `holds`.
    let mut replay =
        Client::bring_passkey(&session, &passkey_request("disc-0", Ceremony::Get, |_| {})).await;
    assert_eq!(replay.next().await, refusal("disc-0", Refusal::Replayed));
    assert_eq!(holds_calls.load(Ordering::SeqCst), 3);

    // Avoid unused warning on `mut vault`.
    let _ = &mut vault;
}
