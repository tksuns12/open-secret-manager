use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use osm_browser_link::{
    Caller, CardField, CardFrame, CardReply, CardValues, Ceremony, Failure, FillReply, Origin,
    PasskeyReply, PasskeyRequest, Refusal, Response,
};
use osm_vault_core::{
    card,
    passkey::{self, FoundPasskey, Registering, Signing, UserVerification},
    ItemKind, ItemSummary, UnlockSession, Vault,
};
use tokio::sync::{oneshot, watch};

use crate::broker::{Asked, Broker};

/// The time limits of a request.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// How long the owner has to decide, unlocking included.
    pub decide_within: Duration,
    /// How often the extension is told that the owner has not decided yet.
    pub remind_every: Duration,
    /// How long a connection has to send its request, and to take an
    /// answer.
    pub exchange_within: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            decide_within: Duration::from_secs(120),
            remind_every: Duration::from_secs(20),
            exchange_within: Duration::from_secs(5),
        }
    }
}

/// What the owner is asked to decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choices {
    pub request_id: String,
    /// The origin of the page that would be filled.
    pub origin: String,
    /// The kind of browser the request came from.
    pub browser: &'static str,
    /// How long the owner still has.
    pub seconds_left: u64,
    /// The unlock the logins were listed under. `None` while the vault is
    /// locked or there is none: the owner has to unlock it to choose.
    pub session: Option<UnlockSession>,
    /// The logins stored for exactly that origin. Empty while locked, and
    /// for a card's request.
    pub logins: Vec<ItemSummary>,
    /// For a card's request: what it asks of a card.
    pub card: Option<CardChoices>,
    /// For a passkey's request: what the page asks.
    pub passkey: Option<PasskeyChoices>,
}

/// What a page's request for a passkey asks, and what may answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyChoices {
    pub ceremony: Ceremony,
    /// The site the passkey is for, as the page named it and the app
    /// checked it against the page's origin.
    pub rp_id: String,
    /// For a new passkey: the site's name for itself, as it gave it, and
    /// the account it is for.
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// Whether the owner is to be verified, as the site asked.
    pub verification: UserVerification,
    /// To sign in: the passkeys the vault holds for the site, of those it
    /// takes. Empty while locked.
    pub passkeys: Vec<FoundPasskey>,
    /// For a new passkey: the logins of the site it may go on instead of a
    /// new login. Empty while locked.
    pub logins: Vec<ItemSummary>,
}

/// Says, for a page's sign-in, whether the vault holds a passkey for the
/// site (the RP ID) of those it takes (the credential IDs it names, if
/// any): `Some(false)` when the vault is unlocked and holds none, `None`
/// when that cannot be told now.
pub type HoldsPasskey = dyn Fn(&str, &[Vec<u8>]) -> Option<bool> + Send + Sync;

/// What a card's request asks, and what may answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardChoices {
    /// The documents to be filled, each with its origin and fields: the
    /// page itself, and frames in it of the same origin or another.
    pub frames: Vec<CardFrame>,
    /// Every card the vault holds, which any page may be given, but those
    /// two devices changed at once. Empty while locked.
    pub cards: Vec<ItemSummary>,
}

/// Why the owner's choice released nothing.
#[derive(Debug)]
pub enum Refused {
    /// The request is not waiting any more: it was withdrawn, ran out of
    /// time, or was decided already.
    NotPending,
    /// The vault is locked, or was locked since the owner was shown the
    /// logins. The request keeps waiting.
    Locked,
    /// The chosen item is not a login for the page's origin, or, for a
    /// card's request, not a card that may be filled. The request keeps
    /// waiting.
    NotForThisPage,
    /// The site requires the owner to be verified, and the owner was not.
    /// The request keeps waiting.
    NotVerified,
    /// The vault holds a passkey the site says it has for the account: the
    /// page is told so, and the request is over.
    Exists,
    /// The vault could not be read. The request keeps waiting.
    Vault(osm_vault_core::Error),
}

/// A connection's end of its request: what it is told when the request is
/// decided.
type Answer = oneshot::Sender<Response>;

struct State {
    broker: Broker,
    /// The connection that brought the waiting request.
    answer: Option<(u64, String, Answer)>,
}

/// Where a request from the browser waits for the owner.
pub struct Desk {
    pub(crate) config: Config,
    state: Mutex<State>,
    /// Counts every change to what is waiting.
    changed: watch::Sender<u64>,
    /// Answers a page's sign-in at once when the vault holds no passkey it
    /// takes (see [`Desk::answer_sign_ins_with`]).
    holds: Mutex<Option<Box<HoldsPasskey>>>,
}

impl Desk {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(State {
                broker: Broker::new(config.decide_within),
                answer: None,
            }),
            changed: watch::Sender::new(0),
            holds: Mutex::new(None),
        })
    }

    /// From now on, a page's sign-in that the vault holds no passkey for,
    /// as `holds` tells, is answered at once with `no_passkey`, before the
    /// owner is asked anything, so the browser's own passkeys answer it
    /// without this app coming forward.
    pub fn answer_sign_ins_with(&self, holds: Box<HoldsPasskey>) {
        *self
            .holds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(holds);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Nothing is left half-done by a panic while it is held.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn announce(&self) {
        self.changed.send_modify(|count| *count += 1);
    }

    /// Changes whenever a request arrives, ends, or is decided.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// What the owner is asked now, if anything. With an unlocked vault it
    /// lists the logins for the page's origin; a locked or missing vault
    /// shows the request without them.
    pub fn choices(&self, vault: Option<&Vault>) -> osm_vault_core::Result<Option<Choices>> {
        let now = Instant::now();
        let state = self.state();
        let Some(pending) = state.broker.pending(now) else {
            return Ok(None);
        };
        let session = vault.and_then(Vault::unlock_session);
        let unlocked = vault.filter(|_| session.is_some());
        let (logins, card) = match (&pending.asked, unlocked) {
            (Asked::Login(_), Some(vault)) => (vault.logins_for_origin(&pending.origin)?, None),
            (Asked::Login(_), None) => (Vec::new(), None),
            (Asked::Passkey(..), _) => (Vec::new(), None),
            (Asked::Card(request), vault) => {
                let cards = match vault {
                    Some(vault) => vault
                        .list()?
                        .into_iter()
                        .filter(|item| item.kind == ItemKind::Card && !item.conflict)
                        .collect(),
                    None => Vec::new(),
                };
                let frames = request.frames.clone();
                (Vec::new(), Some(CardChoices { frames, cards }))
            }
        };
        let passkey = match &pending.asked {
            Asked::Passkey(ceremony, request) => {
                passkey_choices(*ceremony, request, &pending.origin, unlocked)?
            }
            _ => None,
        };
        Ok(Some(Choices {
            request_id: pending.asked.request_id().to_owned(),
            origin: pending.origin.to_string(),
            browser: pending.caller.browser(),
            seconds_left: pending.deadline.saturating_duration_since(now).as_secs(),
            session,
            logins,
            card,
            passkey,
        }))
    }

    /// The owner chose the browser's own passkeys for the waiting passkey's
    /// request: the page asks the browser instead. Says whether it was
    /// waiting.
    pub fn use_browser(&self, request_id: &str) -> bool {
        let mut state = self.state();
        let now = Instant::now();
        let from_page = state.broker.pending(now).is_some_and(|pending| {
            pending.asked.request_id() == request_id && pending.asked.started_by_page()
        });
        if !from_page {
            return false;
        }
        let Some(pending) = state.broker.take(request_id, now) else {
            return false;
        };
        let _ = self.answer(
            state,
            pending.ticket,
            Response::refusal(request_id, Refusal::UseBrowser),
        );
        true
    }

    /// The waiting passkey's request of `ceremony` with this ID, if it is
    /// one, and the page's origin.
    fn waiting_passkey(
        &self,
        state: &State,
        request_id: &str,
        wanted: Ceremony,
        now: Instant,
    ) -> Result<(PasskeyRequest, Origin), Refused> {
        let pending = state
            .broker
            .pending(now)
            .filter(|pending| pending.asked.request_id() == request_id)
            .ok_or(Refused::NotPending)?;
        match &pending.asked {
            Asked::Passkey(ceremony, request) if *ceremony == wanted => {
                Ok((request.clone(), pending.origin.clone()))
            }
            _ => Err(Refused::NotForThisPage),
        }
    }

    /// The owner chose to save the passkey the waiting request asks for:
    /// on the login `into`, or else on a new login for the site. `verified`
    /// says the owner was verified for this request just now. If the vault
    /// is still in the unlock `session`, the passkey is made and saved, and
    /// what the page's call returns is sent as the answer. A site that has
    /// one of the vault's passkeys for the account, as it says, is told so
    /// instead, and the request is over ([`Refused::Exists`]).
    pub fn approve_passkey_create(
        &self,
        request_id: &str,
        session: UnlockSession,
        vault: &mut Vault,
        into: Option<&str>,
        verified: bool,
    ) -> Result<(), Refused> {
        if vault.unlock_session() != Some(session) {
            return Err(Refused::Locked);
        }
        let now = Instant::now();
        let state = self.state();
        let (request, origin) = self.waiting_passkey(&state, request_id, Ceremony::Create, now)?;
        let registering = Registering::from_options(&request.options, Some(&origin))
            .map_err(|_| Refused::NotPending)?;
        if registering.user_verification == UserVerification::Required && !verified {
            return Err(Refused::NotVerified);
        }
        // Asked only now that the owner chose to save, so that a site learns
        // nothing of the vault before.
        if vault
            .holds_passkey(&registering.rp_id, &registering.exclude)
            .map_err(vault_refused)?
        {
            let mut state = state;
            let pending = state
                .broker
                .take(request_id, now)
                .ok_or(Refused::NotPending)?;
            self.answer(
                state,
                pending.ticket,
                Response::refusal(request_id, Refusal::PasskeyExists),
            )?;
            return Err(Refused::Exists);
        }
        if let Some(id) = into {
            let found = vault.get(id).map_err(vault_refused)?;
            if found.item.kind != ItemKind::Login || found.conflict {
                return Err(Refused::NotForThisPage);
            }
        }
        let created = registering
            .create(verified, unix_now())
            .map_err(Refused::Vault)?;
        let client_data = passkey::client_data(
            passkey::Ceremony::Create,
            &registering.challenge,
            &origin.to_string(),
        );
        let credential = created.registration.response_json(&client_data);
        // Saved before it is sent: a passkey the site has is one the vault
        // has.
        match into {
            Some(id) => {
                let revision = vault.get(id).map_err(vault_refused)?.revision;
                vault
                    .add_passkey(id, &revision, created.passkey)
                    .map_err(vault_refused)?;
            }
            None => {
                vault
                    .save_passkey_as_login(created.passkey, &registering.rp_id)
                    .map_err(vault_refused)?;
            }
        }
        self.send_passkey(state, request_id, &request, credential, now)
    }

    /// The owner chose the passkey `credential_id` of the login `item_id`
    /// for the waiting sign-in. `verified` as for
    /// [`Desk::approve_passkey_create`]. If the vault is still in the
    /// unlock `session` and the passkey is one the site takes, what the
    /// page's call returns is sent as the answer.
    pub fn approve_passkey_get(
        &self,
        request_id: &str,
        session: UnlockSession,
        vault: &Vault,
        item_id: &str,
        credential_id: &str,
        verified: bool,
    ) -> Result<(), Refused> {
        if vault.unlock_session() != Some(session) {
            return Err(Refused::Locked);
        }
        let now = Instant::now();
        let state = self.state();
        let (request, origin) = self.waiting_passkey(&state, request_id, Ceremony::Get, now)?;
        let signing = Signing::from_options(&request.options, Some(&origin))
            .map_err(|_| Refused::NotPending)?;
        if signing.user_verification == UserVerification::Required && !verified {
            return Err(Refused::NotVerified);
        }
        // The vault decides whether the site takes it, whatever the owner
        // was shown.
        let taken = vault
            .passkeys_for(&signing.rp_id, &signing.allowed)
            .map_err(vault_refused)?
            .iter()
            .any(|found| found.item_id == item_id && found.passkey.credential_id == credential_id);
        if !taken {
            return Err(Refused::NotForThisPage);
        }
        let client_data = passkey::client_data(
            passkey::Ceremony::Get,
            &signing.challenge,
            &origin.to_string(),
        );
        let assertion = vault
            .sign_with_passkey(
                item_id,
                credential_id,
                &signing.rp_id,
                &passkey::client_data_hash(&client_data),
                verified,
                unix_now(),
            )
            .map_err(vault_refused)?;
        let credential = assertion.response_json(&client_data);
        self.send_passkey(state, request_id, &request, credential, now)
    }

    /// Ends the waiting passkey's request with `credential`, as the answer.
    fn send_passkey(
        &self,
        mut state: MutexGuard<'_, State>,
        request_id: &str,
        request: &PasskeyRequest,
        credential: String,
        now: Instant,
    ) -> Result<(), Refused> {
        let pending = state
            .broker
            .take(request_id, now)
            .ok_or(Refused::NotPending)?;
        let reply = Response::PasskeyReply(PasskeyReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            origin: request.origin.clone(),
            credential,
        });
        self.answer(state, pending.ticket, reply)
    }

    /// The owner turned the request down. Says whether it was waiting.
    pub fn deny(&self, request_id: &str) -> bool {
        let mut state = self.state();
        let Some(pending) = state.broker.take(request_id, Instant::now()) else {
            return false;
        };
        if let Some((ticket, _, answer)) = state.answer.take() {
            if ticket == pending.ticket {
                let _ = answer.send(Response::refusal(request_id, Refusal::Denied));
            }
        }
        drop(state);
        self.announce();
        true
    }

    /// The owner chose a login for the waiting request. `session` is the
    /// unlock the choices were listed under. If the vault is still in that
    /// unlock and the login is one for the page's origin, its user name and
    /// password are sent as the answer, and the request is over.
    pub fn approve(
        &self,
        request_id: &str,
        item_id: &str,
        session: UnlockSession,
        vault: &Vault,
    ) -> Result<(), Refused> {
        // A lock ends what the owner chose under it, even if the vault has
        // been unlocked again since.
        if vault.unlock_session() != Some(session) {
            return Err(Refused::Locked);
        }
        let now = Instant::now();
        let mut state = self.state();
        let origin = state
            .broker
            .pending(now)
            .filter(|pending| pending.asked.request_id() == request_id)
            .map(|pending| match pending.asked {
                Asked::Login(_) => Ok(pending.origin.clone()),
                Asked::Card(_) | Asked::Passkey(..) => Err(Refused::NotForThisPage),
            })
            .ok_or(Refused::NotPending)??;
        // The vault decides whether the item is a login for this origin,
        // whatever the owner was shown.
        let credentials = vault
            .credentials_for_origin(item_id, &origin)
            .map_err(|error| match error {
                osm_vault_core::Error::Locked => Refused::Locked,
                osm_vault_core::Error::OriginMismatch | osm_vault_core::Error::NotFound => {
                    Refused::NotForThisPage
                }
                other => Refused::Vault(other),
            })?;
        let pending = state
            .broker
            .take(request_id, now)
            .ok_or(Refused::NotPending)?;
        let Asked::Login(request) = &pending.asked else {
            return Err(Refused::NotPending);
        };
        let reply = Response::FillReply(FillReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            frame_id: request.frame_id,
            document_id: request.document_id.clone(),
            origin: request.origin.clone(),
            username: credentials.username.clone(),
            password: credentials.password.clone(),
        });
        self.answer(state, pending.ticket, reply)
    }

    /// The owner chose a card for the waiting card's request, under
    /// `session`. If the vault is still in that unlock and the item is a
    /// card no two devices changed at once, its fields go as the answer:
    /// only those some document of the request asks for. The request is
    /// then over.
    pub fn approve_card(
        &self,
        request_id: &str,
        item_id: &str,
        session: UnlockSession,
        vault: &Vault,
    ) -> Result<(), Refused> {
        if vault.unlock_session() != Some(session) {
            return Err(Refused::Locked);
        }
        let now = Instant::now();
        let mut state = self.state();
        let asks = state
            .broker
            .pending(now)
            .filter(|pending| pending.asked.request_id() == request_id)
            .map(|pending| match &pending.asked {
                Asked::Card(request) => Ok(move |field| request.asks(field)),
                Asked::Login(_) | Asked::Passkey(..) => Err(Refused::NotForThisPage),
            })
            .ok_or(Refused::NotPending)??;
        let found = vault.get(item_id).map_err(|error| match error {
            osm_vault_core::Error::Locked => Refused::Locked,
            osm_vault_core::Error::NotFound => Refused::NotForThisPage,
            other => Refused::Vault(other),
        })?;
        if found.item.kind != ItemKind::Card || found.conflict {
            return Err(Refused::NotForThisPage);
        }
        let field = |name: &str, wanted: bool| {
            wanted
                .then(|| found.item.custom_fields.get(name).cloned())
                .flatten()
                .unwrap_or_default()
        };
        let month = asks(CardField::ExpiryMonth) || asks(CardField::Expiry);
        let year = asks(CardField::ExpiryYear) || asks(CardField::Expiry);
        let mut number = field(card::NUMBER, asks(CardField::Number));
        let card = CardValues {
            cardholder: field(card::CARDHOLDER, asks(CardField::Cardholder)),
            number: number.chars().filter(char::is_ascii_digit).collect(),
            expiry_month: field(card::EXPIRY_MONTH, month),
            expiry_year: field(card::EXPIRY_YEAR, year),
            security_code: field(card::SECURITY_CODE, asks(CardField::SecurityCode)),
        };
        zeroize::Zeroize::zeroize(&mut number);
        let pending = state
            .broker
            .take(request_id, now)
            .ok_or(Refused::NotPending)?;
        let Asked::Card(request) = &pending.asked else {
            return Err(Refused::NotPending);
        };
        let reply = Response::CardReply(CardReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            top_origin: request.top_origin.clone(),
            frames: request.frames.clone(),
            card,
        });
        self.answer(state, pending.ticket, reply)
    }

    /// Sends the owner's decision to the connection that brought request
    /// `ticket`. Sent while the state is held, so that a connection ending
    /// its request at this instant either finds the answer or prevents it.
    fn answer(
        &self,
        mut state: MutexGuard<'_, State>,
        ticket: u64,
        reply: Response,
    ) -> Result<(), Refused> {
        let sent = match state.answer.take() {
            // If the connection is gone the reply is dropped here, unsent.
            Some((waiting, _, answer)) if waiting == ticket => answer.send(reply).is_ok(),
            _ => false,
        };
        drop(state);
        self.announce();
        sent.then_some(()).ok_or(Refused::NotPending)
    }

    /// Takes a request from a connection. Returns the ticket that names it,
    /// when its time is up, and where its answer will arrive.
    pub(crate) fn submit(
        &self,
        caller: Caller,
        asked: Asked,
    ) -> Result<(u64, Instant, oneshot::Receiver<Response>), Failure> {
        let request_id = asked.request_id().to_owned();
        // A sign-in the vault holds no passkey for is the browser's to answer,
        // before the owner is asked anything.
        if let Some(signing) = asked.sign_in() {
            let holds = self
                .holds
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if holds
                .as_ref()
                .is_some_and(|holds| holds(&signing.rp_id, &signing.allowed) == Some(false))
            {
                return Err(Failure::new(&request_id, Refusal::NoPasskey));
            }
        }
        let now = Instant::now();
        let mut state = self.state();
        // A fill the owner starts takes the place of a request a page
        // started, which the page's browser then answers itself.
        let from_page = state
            .broker
            .pending(now)
            .filter(|pending| pending.asked.started_by_page() && !asked.started_by_page())
            .map(|pending| pending.ticket);
        if let Some(ticket) = from_page {
            state.broker.withdraw(ticket);
            if let Some((waiting, page, answer)) = state.answer.take() {
                if waiting == ticket {
                    let _ = answer.send(Response::refusal(&page, Refusal::Busy));
                } else {
                    state.answer = Some((waiting, page, answer));
                }
            }
        }
        let (ticket, deadline) = match state.broker.submit(caller, asked, now) {
            Ok(pending) => (pending.ticket, pending.deadline),
            // An ID that is not a plain one is not repeated back.
            Err(Refusal::InvalidMessage) => return Err(Failure::unnamed(Refusal::InvalidMessage)),
            Err(code) => return Err(Failure::new(&request_id, code)),
        };
        let (answer, answered) = oneshot::channel();
        // A request whose time ran out just now may not have been told yet.
        if let Some((_, expired, answer)) = state.answer.replace((ticket, request_id, answer)) {
            let _ = answer.send(Response::refusal(&expired, Refusal::Expired));
        }
        drop(state);
        self.announce();
        Ok((ticket, deadline, answered))
    }

    /// Ends a request without a decision: its connection closed or its time
    /// ran out.
    pub(crate) fn withdraw(&self, ticket: u64) {
        let mut state = self.state();
        let waiting = state.broker.withdraw(ticket);
        if state
            .answer
            .as_ref()
            .is_some_and(|(waiting, _, _)| *waiting == ticket)
        {
            state.answer = None;
        }
        drop(state);
        if waiting {
            self.announce();
        }
    }
}

/// What a passkey's request asks, read from the site's options; with the
/// vault's passkeys or logins for it while `vault` is unlocked.
fn passkey_choices(
    ceremony: Ceremony,
    request: &PasskeyRequest,
    origin: &Origin,
    vault: Option<&Vault>,
) -> osm_vault_core::Result<Option<PasskeyChoices>> {
    Ok(match ceremony {
        Ceremony::Create => {
            let Ok(asked) = Registering::from_options(&request.options, Some(origin)) else {
                return Ok(None);
            };
            let logins = match vault {
                Some(vault) => vault.logins_for_site(&asked.rp_id)?,
                None => Vec::new(),
            };
            Some(PasskeyChoices {
                ceremony,
                verification: asked.user_verification,
                rp_name: asked.rp_name.clone(),
                user_name: asked.user_name.clone(),
                user_display_name: asked.user_display_name.clone(),
                rp_id: asked.rp_id.clone(),
                passkeys: Vec::new(),
                logins,
            })
        }
        Ceremony::Get => {
            let Ok(asked) = Signing::from_options(&request.options, Some(origin)) else {
                return Ok(None);
            };
            let passkeys = match vault {
                Some(vault) => vault.passkeys_for(&asked.rp_id, &asked.allowed)?,
                None => Vec::new(),
            };
            Some(PasskeyChoices {
                ceremony,
                verification: asked.user_verification,
                rp_id: asked.rp_id,
                rp_name: String::new(),
                user_name: String::new(),
                user_display_name: String::new(),
                passkeys,
                logins: Vec::new(),
            })
        }
    })
}

/// A vault's refusal, as the owner's choice is refused.
fn vault_refused(error: osm_vault_core::Error) -> Refused {
    match error {
        osm_vault_core::Error::Locked => Refused::Locked,
        osm_vault_core::Error::NotFound
        | osm_vault_core::Error::OriginMismatch
        | osm_vault_core::Error::Unresolved => Refused::NotForThisPage,
        other => Refused::Vault(other),
    }
}

/// The time, in seconds since 1970, for a passkey's date and counter.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
