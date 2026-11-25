use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Origin;

/// The protocol version of a login's request and of a withdrawal, which
/// stay at 1: the extension updates apart from the app, and an older app
/// keeps understanding them.
pub const VERSION: u32 = 1;

/// The protocol version of a card's request, which came later (Phase 17):
/// an app that does not know it refuses it by its version or its type.
pub const CARD_VERSION: u32 = 2;

/// The protocol version of a passkey's request (Phase 18), the same as a
/// card's: an app from before refuses it by its type.
pub const PASSKEY_VERSION: u32 = 2;

/// The most documents of a tab one card request may name.
const MAX_FRAMES: usize = 8;

/// The largest site's options a passkey's request carries, in bytes of
/// JSON. A message is at most 64 KiB, and a site's options are a few
/// hundred bytes.
pub const MAX_PASSKEY_OPTIONS: usize = 32 * 1024;

/// The name browsers know the native messaging host by.
pub const HOST_NAME: &str = "org.opensecretmanager.native";

/// The Chromium extension loaded unpacked, as its README says. Its ID
/// follows from the `key` in the extension's Chromium manifest.
pub const CHROMIUM_EXTENSION_ID: &str = "hjgekjgkjnakgmiopldddikdkcjhnmge";

/// The same extension from the Chrome Web Store, which gives an extension
/// an ID of its own and keeps its key.
pub const CHROMIUM_STORE_EXTENSION_ID: &str = "pnjdoenkfffomcidikbkcegcpgipdjog";

/// The Chromium extensions the host answers: in debug builds (or with the
/// `allow-unpacked-chromium` feature) both the unpacked development copy and
/// the Chrome Web Store's; in release builds only the Chrome Web Store's.
#[cfg(any(debug_assertions, feature = "allow-unpacked-chromium"))]
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &[CHROMIUM_EXTENSION_ID, CHROMIUM_STORE_EXTENSION_ID];

/// The Chromium extensions the host answers: in release builds only the Chrome
/// Web Store's extension ID is trusted (enable `allow-unpacked-chromium` for
/// local unpacked development against a release binary).
#[cfg(not(any(debug_assertions, feature = "allow-unpacked-chromium")))]
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &[CHROMIUM_STORE_EXTENSION_ID];

/// The one Firefox extension the host answers: the ID in the extension's
/// Firefox manifest.
pub const FIREFOX_EXTENSION_ID: &str = "extension@opensecretmanager.org";

/// Upper bound on a request ID or a document ID.
const MAX_ID: usize = 64;

/// IDs are made by the extension. Keeping them to plain characters means
/// one can be echoed, shown, and logged as it is.
fn is_id(text: &str) -> bool {
    (1..=MAX_ID).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Why a request got no login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Not a message of this protocol.
    InvalidMessage,
    /// A message of a kind this version does not have.
    UnsupportedMessage,
    UnsupportedVersion,
    /// The host was started by something other than the allowed extension.
    ExtensionNotAllowed,
    /// The page's origin is not an HTTPS origin as a browser writes one.
    OriginRejected,
    /// The request is for a frame inside the page, not the page itself.
    FrameRejected,
    /// The desktop app is not running, or what answered was not it.
    DesktopSessionUnavailable,
    /// Another request is waiting for the owner.
    Busy,
    /// A request with this ID was made before.
    Replayed,
    /// The owner turned the request down.
    Denied,
    /// The extension withdrew the request.
    Cancelled,
    /// The owner did not decide in time.
    Expired,
    /// The vault holds no passkey the site takes (Phase 18): the browser's
    /// own may answer.
    NoPasskey,
    /// The site's request is not one this app answers, such as one for a
    /// domain no passkey may be for: the browser's own may answer.
    PasskeyRefused,
    /// The vault holds a passkey the site says it already has for the
    /// account, so another is not made.
    PasskeyExists,
    /// The owner chose the browser's own passkeys for this request.
    UseBrowser,
}

/// Asks for a login to be filled into one document of one tab.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FillRequest {
    pub version: u32,
    /// Chosen by the extension, at random, for this one request.
    pub request_id: String,
    pub tab_id: i64,
    /// Always 0, the page itself: frames inside a page are not filled.
    pub frame_id: i64,
    /// Names the document the request was made in; a navigation makes
    /// another.
    pub document_id: String,
    /// The page's origin, as the browser reports it for the tab.
    pub origin: String,
}

impl FillRequest {
    /// Checks everything that can be checked without a vault and returns
    /// the page's origin.
    pub fn check(&self) -> Result<Origin, Refusal> {
        if self.version != VERSION {
            return Err(Refusal::UnsupportedVersion);
        }
        if !is_id(&self.request_id) || !is_id(&self.document_id) || self.tab_id < 0 {
            return Err(Refusal::InvalidMessage);
        }
        if self.frame_id != 0 {
            return Err(Refusal::FrameRejected);
        }
        Origin::parse(&self.origin).ok_or(Refusal::OriginRejected)
    }
}

/// What a field of a card form asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardField {
    Number,
    Cardholder,
    /// The month and the year in one field.
    Expiry,
    ExpiryMonth,
    ExpiryYear,
    SecurityCode,
}

/// A document of the tab with a card's fields: the page itself (frame 0) or
/// a frame inside it, with its own origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardFrame {
    pub frame_id: i64,
    /// Names the document; a navigation makes another.
    pub document_id: String,
    /// The document's own origin, as the browser reports it.
    pub origin: String,
    /// What its fields ask for, each once.
    pub fields: Vec<CardField>,
}

/// Asks for a card to be filled into one tab: into each document named,
/// the fields it asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardRequest {
    pub version: u32,
    /// Chosen by the extension, at random, for this one request.
    pub request_id: String,
    pub tab_id: i64,
    /// The page's origin, as the browser reports it for the tab.
    pub top_origin: String,
    /// At least one, at most eight, each frame once.
    pub frames: Vec<CardFrame>,
}

impl CardRequest {
    /// Checks everything that can be checked without a vault and returns
    /// the page's origin. Each document must be an HTTPS origin as a
    /// browser writes one, and the page itself, if named, the page's.
    pub fn check(&self) -> Result<Origin, Refusal> {
        if self.version != CARD_VERSION {
            return Err(Refusal::UnsupportedVersion);
        }
        if !is_id(&self.request_id)
            || self.tab_id < 0
            || self.frames.is_empty()
            || self.frames.len() > MAX_FRAMES
        {
            return Err(Refusal::InvalidMessage);
        }
        let mut frames = std::collections::BTreeSet::new();
        let mut seen_fields = std::collections::BTreeSet::new();
        for frame in &self.frames {
            if !is_id(&frame.document_id)
                || frame.frame_id < 0
                || !frames.insert(frame.frame_id)
                || frame.fields.is_empty()
            {
                return Err(Refusal::InvalidMessage);
            }
            for &field in &frame.fields {
                if !seen_fields.insert(field) {
                    return Err(Refusal::InvalidMessage);
                }
            }
        }
        if !seen_fields.contains(&CardField::Number) {
            return Err(Refusal::InvalidMessage);
        }
        let top = Origin::parse(&self.top_origin).ok_or(Refusal::OriginRejected)?;
        let mut other_origin: Option<Origin> = None;
        for frame in &self.frames {
            let origin = Origin::parse(&frame.origin).ok_or(Refusal::OriginRejected)?;
            if frame.frame_id == 0 && origin != top {
                return Err(Refusal::FrameRejected);
            }
            if origin != top {
                match &other_origin {
                    None => other_origin = Some(origin),
                    Some(existing) if existing != &origin => return Err(Refusal::FrameRejected),
                    Some(_) => {}
                }
            }
        }
        Ok(top)
    }

    /// Whether some document asks for `field`.
    pub fn asks(&self, field: CardField) -> bool {
        self.frames
            .iter()
            .any(|frame| frame.fields.contains(&field))
    }
}

/// Which call a page made of WebAuthn.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ceremony {
    /// `navigator.credentials.create`: make a passkey.
    Create,
    /// `navigator.credentials.get`: sign in with one.
    Get,
}

/// Asks for a passkey for the page itself of one tab, to make one or to
/// sign in with one: what a page asked of `navigator.credentials`, which
/// the extension hands on as it was asked, while the owner was using the
/// page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyRequest {
    pub version: u32,
    /// Chosen by the extension, at random, for this one request.
    pub request_id: String,
    pub tab_id: i64,
    /// The page's origin, as the browser told the extension the document's
    /// origin.
    pub origin: String,
    /// The site's options, as WebAuthn's JSON writes them
    /// (`PublicKeyCredentialCreationOptionsJSON` or
    /// `PublicKeyCredentialRequestOptionsJSON`), read by the desktop app.
    pub options: String,
}

impl PasskeyRequest {
    /// Checks everything that can be checked without the site's options and
    /// returns the page's origin.
    pub fn check(&self) -> Result<Origin, Refusal> {
        if self.version != PASSKEY_VERSION {
            return Err(Refusal::UnsupportedVersion);
        }
        if !is_id(&self.request_id)
            || self.tab_id < 0
            || self.options.is_empty()
            || self.options.len() > MAX_PASSKEY_OPTIONS
        {
            return Err(Refusal::InvalidMessage);
        }
        Origin::parse(&self.origin).ok_or(Refusal::OriginRejected)
    }
}

/// Withdraws a request, when its page went away.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    pub version: u32,
    pub request_id: String,
}

/// What the extension sends the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    FillRequest(FillRequest),
    Cancel(Cancel),
    CardRequest(CardRequest),
    PasskeyCreate(PasskeyRequest),
    PasskeyGet(PasskeyRequest),
}

/// A `serde_json::Value` wrapper whose `Deserialize` implementation rejects
/// duplicate object keys at every nesting depth (preventing JSON key-smuggling
/// differentials between `serde_json` last-key-wins and strict parsers).
struct StrictValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = serde_json::Value;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any valid JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Number(v.into()))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Number(v.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(serde_json::Value::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(serde_json::Value::String(v))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut vec = Vec::new();
                while let Some(StrictValue(elem)) = seq.next_element()? {
                    vec.push(elem);
                }
                Ok(serde_json::Value::Array(vec))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, StrictValue(val))) = map.next_entry::<String, StrictValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    values.insert(key, val);
                }
                Ok(serde_json::Value::Object(values))
            }
        }

        deserializer.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

/// Parses `body` as a single JSON value, rejecting duplicate object keys at
/// every nesting level and any trailing bytes.
fn parse_strict_json(body: &[u8]) -> Result<serde_json::Value, ()> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let StrictValue(value) = StrictValue::deserialize(&mut de).map_err(|_| ())?;
    de.end().map_err(|_| ())?;
    Ok(value)
}

/// Deserializes `T` from JSON `body`, rejecting duplicate object keys at every
/// nesting depth and any trailing bytes.
pub fn read_strict<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Refusal> {
    let value = parse_strict_json(body).map_err(|()| Refusal::InvalidMessage)?;
    serde_json::from_value(value).map_err(|_| Refusal::InvalidMessage)
}

impl Request {
    /// Reads and checks one message from the extension. A refusal names
    /// the request it refuses when the message named one. Duplicate JSON keys
    /// at any nesting level are refused as [`Refusal::InvalidMessage`].
    pub fn read(body: &[u8]) -> Result<Self, Failure> {
        let value =
            parse_strict_json(body).map_err(|()| Failure::unnamed(Refusal::InvalidMessage))?;
        let field = |name: &str| value.as_object().and_then(|object| object.get(name));
        let request_id = field("requestId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| is_id(id))
            .map(str::to_owned);
        let refuse = |code| Failure {
            request_id: request_id.clone(),
            code,
        };
        if !value.is_object() {
            return Err(refuse(Refusal::InvalidMessage));
        }
        let version = match field("type").and_then(serde_json::Value::as_str) {
            Some("fill_request" | "cancel") => VERSION,
            Some("card_request") => CARD_VERSION,
            Some("passkey_create" | "passkey_get") => PASSKEY_VERSION,
            Some(_) => return Err(refuse(Refusal::UnsupportedMessage)),
            None => return Err(refuse(Refusal::InvalidMessage)),
        };
        if field("version").and_then(serde_json::Value::as_u64) != Some(u64::from(version)) {
            return Err(refuse(Refusal::UnsupportedVersion));
        }
        let request: Self =
            serde_json::from_value(value.clone()).map_err(|_| refuse(Refusal::InvalidMessage))?;
        match &request {
            Self::FillRequest(fill) => {
                fill.check().map_err(refuse)?;
            }
            Self::CardRequest(card) => {
                card.check().map_err(refuse)?;
            }
            Self::PasskeyCreate(passkey) | Self::PasskeyGet(passkey) => {
                passkey.check().map_err(refuse)?;
            }
            Self::Cancel(cancel) => {
                if !is_id(&cancel.request_id) {
                    return Err(refuse(Refusal::InvalidMessage));
                }
            }
        }
        Ok(request)
    }
}

/// Tells the extension that the desktop session has the request and the
/// owner has not decided yet. Sent at once and then at intervals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Waiting {
    pub request_id: String,
}

/// The login the owner chose, for the one request it answers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FillReply {
    pub request_id: String,
    pub tab_id: i64,
    pub frame_id: i64,
    pub document_id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
}

impl FillReply {
    /// Whether this is a reply to exactly `request`: the same request, tab,
    /// frame, document, and origin.
    pub fn answers(&self, request: &FillRequest) -> bool {
        self.request_id == request.request_id
            && self.tab_id == request.tab_id
            && self.frame_id == request.frame_id
            && self.document_id == request.document_id
            && self.origin == request.origin
    }
}

impl Drop for FillReply {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl fmt::Debug for FillReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillReply")
            .field("request_id", &self.request_id)
            .field("tab_id", &self.tab_id)
            .field("frame_id", &self.frame_id)
            .field("document_id", &self.document_id)
            .field("origin", &self.origin)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

/// A card's fields, for a reply: only those some document of the request
/// asks for, the others empty.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardValues {
    pub cardholder: String,
    /// Its digits only.
    pub number: String,
    pub expiry_month: String,
    pub expiry_year: String,
    pub security_code: String,
}

impl Drop for CardValues {
    fn drop(&mut self) {
        self.cardholder.zeroize();
        self.number.zeroize();
        self.expiry_month.zeroize();
        self.expiry_year.zeroize();
        self.security_code.zeroize();
    }
}

impl fmt::Debug for CardValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CardValues([REDACTED])")
    }
}

/// The card the owner chose, for the one request it answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardReply {
    pub request_id: String,
    pub tab_id: i64,
    pub top_origin: String,
    pub frames: Vec<CardFrame>,
    pub card: CardValues,
}

impl CardReply {
    /// Whether this is a reply to exactly `request`: the same request, tab,
    /// page, and documents, each with the same fields.
    pub fn answers(&self, request: &CardRequest) -> bool {
        self.request_id == request.request_id
            && self.tab_id == request.tab_id
            && self.top_origin == request.top_origin
            && self.frames == request.frames
    }
}

/// What the owner's passkey sends the page, for the one request it answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyReply {
    pub request_id: String,
    pub tab_id: i64,
    pub origin: String,
    /// The credential, as WebAuthn's JSON writes it
    /// (`RegistrationResponseJSON` or `AuthenticationResponseJSON`): what
    /// the page's call returns. It holds no secret: it is for the site.
    pub credential: String,
}

impl PasskeyReply {
    /// Whether this is a reply to exactly `request`: the same request, tab,
    /// and origin.
    pub fn answers(&self, request: &PasskeyRequest) -> bool {
        self.request_id == request.request_id
            && self.tab_id == request.tab_id
            && self.origin == request.origin
    }
}

/// A refusal, for the request it names if it names one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Failure {
    pub request_id: Option<String>,
    pub code: Refusal,
}

impl Failure {
    pub fn new(request_id: &str, code: Refusal) -> Self {
        Self {
            request_id: Some(request_id.to_owned()),
            code,
        }
    }

    pub fn unnamed(code: Refusal) -> Self {
        Self {
            request_id: None,
            code,
        }
    }
}

/// What the extension is sent: by the host, and to the host by the desktop
/// session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Waiting(Waiting),
    FillReply(FillReply),
    Error(Failure),
    CardReply(CardReply),
    PasskeyReply(PasskeyReply),
}

impl Response {
    /// Parses one JSON response frame, rejecting duplicate object keys at
    /// every nesting level and any trailing bytes.
    pub fn read(body: &[u8]) -> Result<Self, Refusal> {
        read_strict(body)
    }

    pub fn refusal(request_id: &str, code: Refusal) -> Self {
        Self::Error(Failure::new(request_id, code))
    }

    /// Whether this is a response to exactly `request`, and so may be
    /// handed on.
    pub fn answers(&self, request: &FillRequest) -> bool {
        match self {
            Self::Waiting(waiting) => waiting.request_id == request.request_id,
            Self::FillReply(reply) => reply.answers(request),
            Self::Error(failure) => {
                failure.request_id.as_deref() == Some(request.request_id.as_str())
            }
            Self::CardReply(_) | Self::PasskeyReply(_) => false,
        }
    }

    /// As [`Response::answers`], for a card's request.
    pub fn answers_card(&self, request: &CardRequest) -> bool {
        match self {
            Self::Waiting(waiting) => waiting.request_id == request.request_id,
            Self::CardReply(reply) => reply.answers(request),
            Self::Error(failure) => {
                failure.request_id.as_deref() == Some(request.request_id.as_str())
            }
            Self::FillReply(_) | Self::PasskeyReply(_) => false,
        }
    }

    /// As [`Response::answers`], for a passkey's request.
    pub fn answers_passkey(&self, request: &PasskeyRequest) -> bool {
        match self {
            Self::Waiting(waiting) => waiting.request_id == request.request_id,
            Self::PasskeyReply(reply) => reply.answers(request),
            Self::Error(failure) => {
                failure.request_id.as_deref() == Some(request.request_id.as_str())
            }
            Self::FillReply(_) | Self::CardReply(_) => false,
        }
    }

    /// Whether nothing follows it for its request.
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Waiting(_))
    }
}

/// The extension that started the host, as the browser named it on the
/// host's command line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "browser", content = "extension", rename_all = "snake_case")]
pub enum Caller {
    /// A Chromium browser gives the extension's origin,
    /// `chrome-extension://<id>/`.
    Chromium(String),
    /// Firefox gives the extension's ID, after the path of the host's
    /// manifest.
    Firefox(String),
}

impl Caller {
    /// Reads the host's arguments, without the program name.
    pub fn from_args(arguments: &[String]) -> Option<Self> {
        match arguments {
            [origin, ..] if origin.starts_with("chrome-extension://") => {
                Some(Self::Chromium(origin.clone()))
            }
            [_manifest, extension, ..] => Some(Self::Firefox(extension.clone())),
            _ => None,
        }
    }

    /// Whether this is an extension the host and the desktop session
    /// answer: in Firefox the one, in a Chromium browser the copy loaded
    /// unpacked or the Chrome Web Store's.
    pub fn is_allowed(&self) -> bool {
        match self {
            Self::Chromium(origin) => origin
                .strip_prefix("chrome-extension://")
                .and_then(|rest| rest.strip_suffix('/'))
                .is_some_and(|id| CHROMIUM_EXTENSION_IDS.contains(&id)),
            Self::Firefox(extension) => extension == FIREFOX_EXTENSION_ID,
        }
    }

    /// The kind of browser, for showing to the owner.
    pub fn browser(&self) -> &'static str {
        match self {
            Self::Chromium(_) => "Chromium",
            Self::Firefox(_) => "Firefox",
        }
    }
}

/// What the host passes to the desktop session: a request it has checked,
/// and who made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Forwarded {
    pub caller: Caller,
    pub request: FillRequest,
}

/// What the host passes to the desktop session for a card: a request it
/// has checked, and who made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardedCard {
    pub caller: Caller,
    pub card: CardRequest,
}

/// What the host passes to the desktop session for a passkey: a request it
/// has checked, which call it is, and who made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardedPasskey {
    pub caller: Caller,
    pub ceremony: Ceremony,
    pub passkey: PasskeyRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILL: &str = r#"{"type":"fill_request","version":1,"requestId":"7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11","tabId":12,"frameId":0,"documentId":"0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f","origin":"https://example.com"}"#;

    fn request() -> FillRequest {
        match Request::read(FILL.as_bytes()).unwrap() {
            Request::FillRequest(request) => request,
            other => panic!("{other:?}"),
        }
    }

    fn refused(body: &str) -> (Option<String>, Refusal) {
        let failure = Request::read(body.as_bytes()).unwrap_err();
        (failure.request_id, failure.code)
    }

    /// `FILL` with one field replaced.
    fn fill_with(field: &str, value: &str) -> String {
        let mut object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(FILL).unwrap();
        object.insert(field.into(), serde_json::from_str(value).unwrap());
        serde_json::to_string(&object).unwrap()
    }

    #[test]
    fn a_fill_request_is_read_with_the_names_the_extension_uses() {
        let request = request();
        assert_eq!(request.version, 1);
        assert_eq!(request.request_id, "7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11");
        assert_eq!(request.tab_id, 12);
        assert_eq!(request.frame_id, 0);
        assert_eq!(request.document_id, "0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f");
        assert_eq!(request.check().unwrap().to_string(), "https://example.com");
        // It is written as it was read.
        let written = serde_json::to_string(&Request::FillRequest(request)).unwrap();
        assert_eq!(written, FILL);

        let cancel = Request::read(br#"{"type":"cancel","version":1,"requestId":"abc"}"#).unwrap();
        assert_eq!(
            cancel,
            Request::Cancel(Cancel {
                version: 1,
                request_id: "abc".into()
            })
        );
    }

    #[test]
    fn anything_else_is_refused_with_the_reason() {
        let id = Some("7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11".to_owned());
        for body in ["", "not json", "[]", "7", "null", r#""fill_request""#, "{}"] {
            assert_eq!(refused(body), (None, Refusal::InvalidMessage), "{body}");
        }
        assert_eq!(
            refused(r#"{"type":"list_logins","version":1,"requestId":"abc"}"#),
            (Some("abc".into()), Refusal::UnsupportedMessage)
        );
        assert_eq!(
            refused(&fill_with("version", "2")),
            (id.clone(), Refusal::UnsupportedVersion)
        );
        assert_eq!(
            refused(&fill_with("version", r#""1""#)),
            (id.clone(), Refusal::UnsupportedVersion)
        );
        assert_eq!(
            refused(r#"{"type":"fill_request","requestId":"abc"}"#),
            (Some("abc".into()), Refusal::UnsupportedVersion)
        );

        // A field too many, a field missing, a field of the wrong kind.
        for body in [
            fill_with("recordId", r#""5a0e""#),
            fill_with("password", r#""hunter2""#),
            fill_with("tabId", r#""12""#),
            fill_with("tabId", "-1"),
            fill_with("tabId", "1.5"),
            fill_with("documentId", r#""""#),
            fill_with("documentId", r#""has space""#),
            fill_with("documentId", &format!(r#""{}""#, "d".repeat(65))),
            fill_with("origin", "null"),
            r#"{"type":"fill_request","version":1,"requestId":"7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11","tabId":12,"frameId":0,"origin":"https://example.com"}"#.to_owned(),
        ] {
            assert_eq!(refused(&body), (id.clone(), Refusal::InvalidMessage), "{body}");
        }
        // A request ID that is not plain is not echoed.
        for bad in [
            r#""""#,
            r#""<script>""#,
            r#""a b""#,
            "7",
            &format!(r#""{}""#, "r".repeat(65)),
        ] {
            assert_eq!(
                refused(&fill_with("requestId", bad)),
                (None, Refusal::InvalidMessage),
                "{bad}"
            );
        }
        assert_eq!(
            refused(r#"{"type":"cancel","version":1,"requestId":"a b"}"#),
            (None, Refusal::InvalidMessage)
        );
        assert_eq!(
            refused(
                r#"{"type":"cancel","version":1,"requestId":"abc","origin":"https://example.com"}"#
            ),
            (Some("abc".into()), Refusal::InvalidMessage)
        );

        assert_eq!(
            refused(&fill_with("frameId", "3")),
            (id.clone(), Refusal::FrameRejected)
        );
        for origin in [
            "http://example.com",
            "https://example.com/",
            "https://example.com/login",
            "https://user@example.com",
            "https://EXAMPLE.com",
            "https://example.com:443",
            "chrome-extension://hjgekjgkjnakgmiopldddikdkcjhnmge",
            "file://",
            "null",
            "",
        ] {
            assert_eq!(
                refused(&fill_with("origin", &format!("{origin:?}"))),
                (id.clone(), Refusal::OriginRejected),
                "{origin}"
            );
        }
    }

    #[test]
    fn a_response_is_handed_on_only_for_the_request_it_answers() {
        let request = request();
        let reply = FillReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            frame_id: 0,
            document_id: request.document_id.clone(),
            origin: request.origin.clone(),
            username: "alice".into(),
            password: "correct horse".into(),
        };
        assert!(reply.answers(&request));
        let written = serde_json::to_string(&Response::FillReply(reply.clone())).unwrap();
        assert_eq!(
            written,
            r#"{"type":"fill_reply","requestId":"7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11","tabId":12,"frameId":0,"documentId":"0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f","origin":"https://example.com","username":"alice","password":"correct horse"}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(&written).unwrap(),
            Response::FillReply(reply.clone())
        );
        let shown = format!("{reply:?}");
        assert!(
            !shown.contains("alice") && !shown.contains("correct horse"),
            "{shown}"
        );

        let changed = |change: fn(&mut FillReply)| {
            let mut other = reply.clone();
            change(&mut other);
            Response::FillReply(other)
        };
        for other in [
            changed(|reply| reply.request_id = "another".into()),
            changed(|reply| reply.tab_id = 13),
            changed(|reply| reply.frame_id = 1),
            changed(|reply| reply.document_id = "another".into()),
            changed(|reply| reply.origin = "https://example.com:8443".into()),
            changed(|reply| reply.origin = "https://www.example.com".into()),
        ] {
            assert!(!other.answers(&request), "{other:?}");
        }
        assert!(Response::FillReply(reply).answers(&request));

        let waiting = Response::Waiting(Waiting {
            request_id: request.request_id.clone(),
        });
        assert!(waiting.answers(&request) && !waiting.is_final());
        assert_eq!(
            serde_json::to_string(&waiting).unwrap(),
            r#"{"type":"waiting","requestId":"7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11"}"#
        );
        let denied = Response::refusal(&request.request_id, Refusal::Denied);
        assert!(denied.answers(&request) && denied.is_final());
        assert_eq!(
            serde_json::to_string(&denied).unwrap(),
            r#"{"type":"error","requestId":"7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11","code":"denied"}"#
        );
        assert!(!Response::refusal("another", Refusal::Denied).answers(&request));
        let unnamed = Response::Error(Failure::unnamed(Refusal::DesktopSessionUnavailable));
        assert!(!unnamed.answers(&request));
        assert_eq!(
            serde_json::to_string(&unnamed).unwrap(),
            r#"{"type":"error","requestId":null,"code":"desktop_session_unavailable"}"#
        );

        // A response with a field too many is not one.
        assert!(serde_json::from_str::<Response>(
            r#"{"type":"waiting","requestId":"abc","password":"x"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Response>(r#"{"type":"fill_reply","requestId":"abc"}"#).is_err()
        );
    }

    const CARD: &str = r#"{"type":"card_request","version":2,"requestId":"c0a1e7f6-0b9c-4f5d-9a57-2f1f8f3f9d11","tabId":12,"topOrigin":"https://shop.example","frames":[{"frameId":0,"documentId":"0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f","origin":"https://shop.example","fields":["cardholder","expiry_month","expiry_year"]},{"frameId":3,"documentId":"a7d6c1b2-6b1c-4c0e-8a6e-0d3b6a522e3f","origin":"https://pay.example.net","fields":["number","security_code"]}]}"#;

    fn card_request() -> CardRequest {
        match Request::read(CARD.as_bytes()).unwrap() {
            Request::CardRequest(request) => request,
            other => panic!("{other:?}"),
        }
    }

    /// `CARD` with `change` made to it.
    fn card_with(change: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut value: serde_json::Value = serde_json::from_str(CARD).unwrap();
        change(&mut value);
        serde_json::to_string(&value).unwrap()
    }

    #[test]
    fn a_card_request_names_each_document_with_its_origin_and_fields() {
        let request = card_request();
        assert_eq!(request.check().unwrap().to_string(), "https://shop.example");
        assert_eq!(request.frames.len(), 2);
        assert_eq!(request.frames[1].origin, "https://pay.example.net");
        assert_eq!(
            request.frames[1].fields,
            [CardField::Number, CardField::SecurityCode]
        );
        assert!(request.asks(CardField::SecurityCode) && !request.asks(CardField::Expiry));
        assert_eq!(
            serde_json::to_string(&Request::CardRequest(request)).unwrap(),
            CARD
        );
    }

    #[test]
    fn a_card_request_out_of_bounds_is_refused_with_the_reason() {
        let id = Some("c0a1e7f6-0b9c-4f5d-9a57-2f1f8f3f9d11".to_owned());
        // A login's version, or a later one.
        for version in ["1", "3"] {
            assert_eq!(
                refused(&card_with(
                    |card| card["version"] = serde_json::from_str(version).unwrap()
                )),
                (id.clone(), Refusal::UnsupportedVersion)
            );
        }
        // And a login's request at the card's version.
        assert_eq!(
            refused(&fill_with("version", "2")).1,
            Refusal::UnsupportedVersion
        );
        for body in [
            card_with(|card| card["frames"] = serde_json::json!([])),
            card_with(|card| {
                let frame = card["frames"][1].clone();
                card["frames"] = serde_json::json!(vec![frame; 9]);
            }),
            card_with(|card| card["frames"][1]["frameId"] = 0.into()),
            card_with(|card| card["frames"][1]["frameId"] = (-1).into()),
            card_with(|card| card["frames"][1]["fields"] = serde_json::json!([])),
            card_with(|card| card["frames"][1]["fields"] = serde_json::json!(["number", "number"])),
            card_with(|card| card["frames"][1]["fields"] = serde_json::json!(["pin"])),
            card_with(|card| card["frames"][1]["documentId"] = "has space".into()),
            card_with(|card| card["frames"][1]["password"] = "x".into()),
            card_with(|card| card["tabId"] = (-1).into()),
            card_with(|card| card["frameId"] = 0.into()),
        ] {
            assert_eq!(
                refused(&body),
                (id.clone(), Refusal::InvalidMessage),
                "{body}"
            );
        }
        for origin in [
            "http://pay.example.net",
            "https://pay.example.net/",
            "null",
            "",
        ] {
            assert_eq!(
                refused(&card_with(
                    |card| card["frames"][1]["origin"] = origin.into()
                )),
                (id.clone(), Refusal::OriginRejected),
                "{origin}"
            );
        }
        assert_eq!(
            refused(&card_with(
                |card| card["topOrigin"] = "https://shop.example:8443".into()
            )),
            (id.clone(), Refusal::FrameRejected)
        );
        // Card number must be requested, fields cannot repeat across frames,
        // and at most one non-top origin may receive card fields.
        assert_eq!(
            refused(&card_with(|card| {
                card["frames"][1]["fields"] = serde_json::json!(["security_code"]);
            })),
            (id.clone(), Refusal::InvalidMessage)
        );
        assert_eq!(
            refused(&card_with(|card| {
                card["frames"][0]["fields"] = serde_json::json!(["cardholder", "security_code"]);
            })),
            (id.clone(), Refusal::InvalidMessage)
        );
        assert_eq!(
            refused(&card_with(|card| {
                card["frames"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "frameId": 4,
                        "documentId": "doc-4",
                        "origin": "https://attacker.example",
                        "fields": ["expiry"],
                    }));
            })),
            (id.clone(), Refusal::FrameRejected)
        );
    }

    #[test]
    fn a_card_reply_is_handed_on_only_for_the_request_it_answers() {
        let request = card_request();
        let reply = CardReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            top_origin: request.top_origin.clone(),
            frames: request.frames.clone(),
            card: CardValues {
                cardholder: "Owner".into(),
                number: "4111111111111111".into(),
                expiry_month: "12".into(),
                expiry_year: "2030".into(),
                security_code: "123".into(),
            },
        };
        let response = Response::CardReply(reply.clone());
        assert!(response.answers_card(&request) && response.is_final());
        assert!(!response.answers(&self::tests::request()));
        let shown = format!("{reply:?}");
        assert!(
            !shown.contains("4111") && !shown.contains("123\""),
            "{shown}"
        );
        let written = serde_json::to_string(&response).unwrap();
        assert!(
            written.starts_with(r#"{"type":"card_reply","requestId":"c0a1e7f6"#),
            "{written}"
        );
        assert_eq!(
            serde_json::from_str::<Response>(&written).unwrap(),
            response
        );

        let changed = |change: fn(&mut CardReply)| {
            let mut other = reply.clone();
            change(&mut other);
            Response::CardReply(other)
        };
        for other in [
            changed(|reply| reply.request_id = "another".into()),
            changed(|reply| reply.tab_id = 13),
            changed(|reply| reply.top_origin = "https://other.example".into()),
            changed(|reply| reply.frames[1].frame_id = 4),
            changed(|reply| reply.frames[1].document_id = "another".into()),
            changed(|reply| reply.frames[1].origin = "https://other.example".into()),
            changed(|reply| reply.frames[0].fields.push(CardField::SecurityCode)),
            changed(|reply| {
                reply.frames.pop();
            }),
        ] {
            assert!(!other.answers_card(&request), "{other:?}");
        }
        // A login's reply does not answer a card's request, nor the reverse.
        assert!(!Response::FillReply(FillReply {
            request_id: request.request_id.clone(),
            tab_id: request.tab_id,
            frame_id: 0,
            document_id: request.frames[0].document_id.clone(),
            origin: request.top_origin.clone(),
            username: "u".into(),
            password: "p".into(),
        })
        .answers_card(&request));
        assert!(Response::Waiting(Waiting {
            request_id: request.request_id.clone()
        })
        .answers_card(&request));
    }

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|&argument| argument.to_owned()).collect()
    }

    #[test]
    fn only_the_one_extension_of_each_browser_is_allowed() {
        let unpacked = format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/");
        let unpacked_caller = Caller::from_args(&arguments(&[&unpacked])).unwrap();
        assert_eq!(unpacked_caller, Caller::Chromium(unpacked.clone()));
        assert_eq!(
            unpacked_caller.is_allowed(),
            cfg!(any(debug_assertions, feature = "allow-unpacked-chromium"))
        );

        // The Chrome Web Store's copy is allowed in every build profile.
        let store = format!("chrome-extension://{CHROMIUM_STORE_EXTENSION_ID}/");
        let caller = Caller::from_args(&arguments(&[&store])).unwrap();
        assert_eq!(caller, Caller::Chromium(store.clone()));
        assert!(caller.is_allowed());
        // On Windows a Chromium browser adds a window handle.
        assert!(
            Caller::from_args(&arguments(&[&store, "--parent-window=0"]))
                .unwrap()
                .is_allowed()
        );
        let firefox = Caller::from_args(&arguments(&[
            "/path/to/org.opensecretmanager.native.json",
            FIREFOX_EXTENSION_ID,
        ]))
        .unwrap();
        assert_eq!(firefox, Caller::Firefox(FIREFOX_EXTENSION_ID.into()));
        assert!(firefox.is_allowed());

        for forged in [
            arguments(&["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]),
            arguments(&[&unpacked[..unpacked.len() - 1]]),
            arguments(&[&format!("{unpacked}x")]),
            arguments(&[&format!(
                "chrome-extension://{CHROMIUM_EXTENSION_ID}.evil.test/"
            )]),
            arguments(&[&format!(
                "chrome-extension://{CHROMIUM_STORE_EXTENSION_ID}.evil.test/"
            )]),
            arguments(&[&format!("chrome-extension://{CHROMIUM_STORE_EXTENSION_ID}")]),
            arguments(&["/path/to/manifest.json", CHROMIUM_STORE_EXTENSION_ID]),
            arguments(&["/path/to/manifest.json", "another@example.org"]),
            arguments(&["/path/to/manifest.json", &unpacked]),
            arguments(&[FIREFOX_EXTENSION_ID, "another@example.org"]),
        ] {
            let caller = Caller::from_args(&forged).unwrap();
            assert!(!caller.is_allowed(), "{forged:?}");
        }
        // Started by hand, or by anything that names no extension.
        assert_eq!(Caller::from_args(&[]), None);
        assert_eq!(Caller::from_args(&arguments(&[FIREFOX_EXTENSION_ID])), None);
        assert_eq!(
            Caller::from_args(&arguments(&["https://example.com/"])),
            None
        );
    }

    #[test]
    fn duplicate_json_keys_are_rejected_in_requests_and_responses() {
        let dup_top = r#"{"type":"fill_request","version":1,"requestId":"abc","tabId":1,"frameId":0,"documentId":"d","origin":"https://evil.test","origin":"https://good.test"}"#;
        assert_eq!(refused(dup_top), (None, Refusal::InvalidMessage));

        let dup_nested = r#"{"type":"card_request","version":2,"requestId":"abc","tabId":1,"topOrigin":"https://shop.test","frames":[{"frameId":0,"documentId":"d","origin":"https://evil.test","origin":"https://shop.test","fields":["number"]}]}"#;
        assert_eq!(refused(dup_nested), (None, Refusal::InvalidMessage));

        let dup_response = r#"{"type":"waiting","requestId":"a","requestId":"b"}"#;
        assert!(Response::read(dup_response.as_bytes()).is_err());
        assert!(Response::read(br#"{"type":"waiting","requestId":"a"}"#).is_ok());
    }

    #[test]
    fn the_chromium_extension_id_follows_from_the_key_in_its_manifest() {
        use base64ct::Encoding;
        use sha2::Digest;

        let manifest = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/browser-extension/manifest.chromium.json"
        ))
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        let key = base64ct::Base64::decode_vec(manifest["key"].as_str().unwrap()).unwrap();
        // A Chromium extension's ID is the first half of the SHA-256 of its
        // public key, each hexadecimal digit written as a letter from a to p.
        let id: String = sha2::Sha256::digest(&key)[..16]
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0xf])
            .map(|digit| char::from(b'a' + digit))
            .collect();
        assert_eq!(id, CHROMIUM_EXTENSION_ID);

        let manifest = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/browser-extension/manifest.firefox.json"
        ))
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(
            manifest["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );
    }

    #[test]
    fn what_the_host_forwards_names_the_caller() {
        let forwarded = Forwarded {
            caller: Caller::Firefox(FIREFOX_EXTENSION_ID.into()),
            request: request(),
        };
        let written = serde_json::to_string(&forwarded).unwrap();
        assert!(
            written.starts_with(
                r#"{"caller":{"browser":"firefox","extension":"extension@opensecretmanager.org"},"request":{"version":1,"#
            ),
            "{written}"
        );
        assert_eq!(
            serde_json::from_str::<Forwarded>(&written).unwrap(),
            forwarded
        );
        assert!(serde_json::from_str::<Forwarded>(&written.replacen(
            "{\"caller\"",
            "{\"extra\":1,\"caller\"",
            1
        ))
        .is_err());
    }
}
