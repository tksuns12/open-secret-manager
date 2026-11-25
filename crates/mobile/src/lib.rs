//! The interface the phone apps use: one device of a vault, which joins
//! from another device by invitation, unlocks with its own password, shows
//! and copies what the vault holds, and stays in sync while the app is
//! open. Everything runs on the same code as the desktop app; the apps add
//! only what the system offers (autofill, secure key storage, lifecycle).
//!
//! The interface is blocking: every call returns when it is done, and the
//! apps make them off their main thread. Calls that reach other devices
//! can take seconds.
//!
//! Secrets cross into the app only where it needs them: a password or a
//! one-time code to copy or fill. What crosses cannot be wiped there. The
//! owner's edits cross the other way, into the shared code, which keeps
//! them only in the vault.
//!
//! On a phone the owner creates, edits, deletes, and restores logins, secure
//! notes, and cards, and saves what another app's login form submitted;
//! identities are read there and edited on a computer, as are conflicts
//! between devices.
//!
//! This crate's own code has no `unsafe`; the foreign function interface
//! that UniFFI generates around it is made of it.

#![deny(unsafe_code)]

mod fill;
mod runtime;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use zeroize::Zeroizing;

pub use crate::fill::{Asks, Filled, Offer, Requester};
use crate::runtime::Runtime;

uniffi::setup_scaffolding!();

/// Why a call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("the vault is locked")]
    Locked,
    #[error("that password or key was rejected")]
    InvalidCredentials,
    #[error("there is no such item")]
    NotFound,
    #[error("this device has no vault")]
    NoVault,
    #[error("this device already has a vault")]
    VaultExists,
    #[error("the vault file here cannot be opened: {reason}")]
    UnreadableVault { reason: String },
    #[error("start joining with an invitation first")]
    NotJoining,
    #[error("use at least {minimum} characters for this device's password")]
    PasswordTooShort { minimum: u32 },
    #[error("the other device did not confirm, or the codes differed")]
    NotConfirmed,
    #[error("the vault's devices did not finish enrolling this device in time")]
    EnrollmentTimeout,
    #[error("this device was removed from its vault")]
    Removed,
    #[error("that is not a valid invitation")]
    InvalidInvitation,
    #[error("the item has no one-time code")]
    NoOneTimeCode,
    #[error("the item has no such field")]
    NoSuchField,
    #[error("that is not an https origin")]
    InvalidOrigin,
    #[error("that login is not for this page")]
    NotForThisPage,
    #[error("that item is not a login")]
    NotALogin,
    #[error("that item is not a card")]
    NotACard,
    /// The login was not chosen for the app that asks, which is filled only
    /// one the owner chose for it.
    #[error("that login was not chosen for this app")]
    NotChosen,
    /// A save went to a login that the form could not be filled with, or
    /// one under another username.
    #[error("that login is not one this form could be saved into")]
    NotForThisForm,
    /// A requester with no origin, or an app with no key.
    #[error("that request names no one a login could go to")]
    InvalidRequester,
    /// A site's request for a passkey that is not answered here (see
    /// [`PasskeyRefusal`]): another provider, or the browser, may answer it.
    #[error("{reason}")]
    PasskeyRefused {
        refusal: PasskeyRefusal,
        reason: String,
    },
    /// The vault holds a passkey the site says it already has for the
    /// account, so another is not made.
    #[error("this vault already holds a passkey for that account")]
    PasskeyExists,
    /// The site requires the owner to be verified in this request, and the
    /// owner was not.
    #[error("the site requires you to be verified")]
    NotVerified,
    #[error("{reason}")]
    InvalidItem { reason: String },
    /// The item changed since it was read, here or on another device.
    #[error("the item changed since it was opened")]
    ChangedElsewhere,
    /// Two devices changed the item at once; a computer resolves that.
    #[error("two devices changed the item at once")]
    InConflict,
    /// Identities are edited on a computer.
    #[error("that kind of item is edited on a computer")]
    NotEditableHere,
    // Not `message`: in Kotlin every exception has one already.
    #[error("{reason}")]
    Network { reason: String },
    #[error("{reason}")]
    Storage { reason: String },
    /// The phone's keystore did not open this device's network key now.
    #[error("this phone's keystore did not answer")]
    KeystoreUnavailable,
    /// The phone's keystore no longer holds the key this device's network
    /// key was sealed with, as after these files were restored onto
    /// another phone: the device has to be removed and joined again.
    #[error("this phone no longer holds this device's network key")]
    KeystoreLost,
}

/// Why a request for a passkey is not answered here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasskeyRefusal {
    /// It is not a request this app reads.
    Malformed,
    /// The site named a domain it may not use passkeys of, or one no
    /// passkey may be for.
    Site,
    /// The site takes no key of the kind this app makes.
    Algorithm,
}

impl From<osm_vault_core::passkey::Refusal> for MobileError {
    fn from(refusal: osm_vault_core::passkey::Refusal) -> Self {
        use osm_vault_core::passkey::Refusal;
        Self::PasskeyRefused {
            refusal: match refusal {
                Refusal::Malformed(_) => PasskeyRefusal::Malformed,
                Refusal::RelyingParty => PasskeyRefusal::Site,
                Refusal::Algorithm => PasskeyRefusal::Algorithm,
            },
            reason: refusal.to_string(),
        }
    }
}

impl From<osm_vault_core::Error> for MobileError {
    fn from(error: osm_vault_core::Error) -> Self {
        use osm_vault_core::Error;
        match error {
            Error::Locked => Self::Locked,
            Error::InvalidCredentials => Self::InvalidCredentials,
            Error::NotFound => Self::NotFound,
            Error::OriginMismatch => Self::NotForThisPage,
            Error::UserVerificationRequired => Self::NotVerified,
            Error::InvalidItem(reason) => Self::InvalidItem { reason },
            Error::Conflict { .. } => Self::ChangedElsewhere,
            Error::Unresolved => Self::InConflict,
            error => Self::Storage {
                reason: error.to_string(),
            },
        }
    }
}

impl From<osm_vault_peer::Error> for MobileError {
    fn from(error: osm_vault_peer::Error) -> Self {
        use osm_vault_peer::Error;
        match error {
            Error::Removed => Self::Removed,
            Error::NotConfirmed => Self::NotConfirmed,
            Error::Vault(error) => error.into(),
            Error::Keystore(osm_vault_peer::KeystoreError::Lost) => Self::KeystoreLost,
            Error::Keystore(_) => Self::KeystoreUnavailable,
            error => Self::Network {
                reason: error.to_string(),
            },
        }
    }
}

impl From<std::io::Error> for MobileError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage {
            reason: error.to_string(),
        }
    }
}

/// The phone's keystore, which seals this device's network (TLS) key so
/// that its files alone do not give it away: the Android Keystore, the iOS
/// Keychain. The app gives its own to [`Device::open`].
#[uniffi::export(with_foreign)]
pub trait PhoneKeystore: Send + Sync {
    /// Seals `key`; what comes back is given to [`PhoneKeystore::unseal`].
    fn seal(&self, key: Vec<u8>) -> Result<Vec<u8>, KeystoreFailure>;
    /// Opens what [`PhoneKeystore::seal`] returned. Not named `open`:
    /// UniFFI writes that name into the C header for Swift as `` `open` ``,
    /// which does not compile.
    fn unseal(&self, sealed: Vec<u8>) -> Result<Vec<u8>, KeystoreFailure>;
}

/// Why the phone's keystore did not seal or open a key.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeystoreFailure {
    /// Not now: locked, refused, or not answering.
    #[error("the keystore did not answer")]
    Unavailable,
    /// The key it was sealed with is not there.
    #[error("the keystore does not hold that key")]
    Lost,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeystoreFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable
    }
}

/// The phone's keystore as the peer store asks for one.
struct ForeignKeystore(Arc<dyn PhoneKeystore>);

impl osm_vault_peer::Keystore for ForeignKeystore {
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>, osm_vault_peer::KeystoreError> {
        self.0
            .seal(key.to_vec())
            .map_err(KeystoreFailure::into_peer)
    }

    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, osm_vault_peer::KeystoreError> {
        self.0
            .unseal(sealed.to_vec())
            .map(Zeroizing::new)
            .map_err(KeystoreFailure::into_peer)
    }
}

impl KeystoreFailure {
    fn into_peer(self) -> osm_vault_peer::KeystoreError {
        match self {
            Self::Unavailable => osm_vault_peer::KeystoreError::Unavailable,
            Self::Lost => osm_vault_peer::KeystoreError::Lost,
        }
    }
}

/// Where this device stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceState {
    /// No vault: it can join one by invitation.
    NoVault,
    /// Joining: the owner compares the codes, then the vault's devices
    /// enroll this one.
    Joining,
    Locked,
    Unlocked,
    /// The vault's devices removed it: it receives nothing more.
    Removed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ItemKind {
    Login,
    SecureNote,
    Identity,
    Card,
}

impl From<osm_vault_core::ItemSummary> for ItemSummary {
    fn from(item: osm_vault_core::ItemSummary) -> Self {
        Self {
            id: item.id,
            title: item.title,
            kind: item.kind.into(),
            username: item.username,
            url: item.url,
            favorite: item.favorite,
            conflict: item.conflict,
            card_ending: item.card_ending,
            brand: item.brand,
            passkeys: item.passkeys as u32,
        }
    }
}

impl From<osm_vault_core::ItemKind> for ItemKind {
    fn from(kind: osm_vault_core::ItemKind) -> Self {
        use osm_vault_core::ItemKind as Kind;
        match kind {
            Kind::Login => Self::Login,
            Kind::SecureNote => Self::SecureNote,
            Kind::Identity => Self::Identity,
            Kind::Card => Self::Card,
        }
    }
}

/// An item as the list shows it. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    /// Two devices changed it at once; a computer resolves that.
    pub conflict: bool,
    /// For a card, the last four digits of its number, which may be shown:
    /// nothing else of the number is here.
    pub card_ending: Option<String>,
    /// For a card, its brand as stored, or else as its number names it.
    pub brand: Option<String>,
    /// How many passkeys a login holds.
    pub passkeys: u32,
}

/// Why a password is called weak (see `osm_vault_core::health`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Weakness {
    TooShort,
    OneKind,
    Common,
    HoldsOwnName,
}

/// A login whose password is weak, and why. Never the password.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct WeakPassword {
    pub id: String,
    pub reasons: Vec<Weakness>,
}

impl std::fmt::Debug for WeakPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakPassword")
            .field("reasons", &self.reasons)
            .finish_non_exhaustive()
    }
}

/// A set of logins that share one password.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReusedPassword {
    pub ids: Vec<String>,
}

// Which logins share a password is not printed, however a log is made.
impl std::fmt::Debug for ReusedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReusedPassword")
            .field("logins", &self.ids.len())
            .finish()
    }
}

/// Which logins hold a weak password or share one: ids and reasons, made
/// when asked for and kept by no one.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordHealth {
    pub weak: Vec<WeakPassword>,
    pub reused: Vec<ReusedPassword>,
}

impl std::fmt::Debug for PasswordHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHealth")
            .field("weak", &self.weak.len())
            .field("reused", &self.reused.len())
            .finish()
    }
}

/// A login's passkey as its page shows it: the site and the account it is
/// for. Never its key.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyDetail {
    /// Names it to [`Device::remove_passkey`].
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    /// In seconds since 1970; 0 when not known.
    pub created_at: u64,
}

impl From<osm_vault_core::PasskeySummary> for PasskeyDetail {
    fn from(passkey: osm_vault_core::PasskeySummary) -> Self {
        Self {
            credential_id: passkey.credential_id,
            rp_id: passkey.rp_id,
            user_name: passkey.user_name,
            user_display_name: passkey.user_display_name,
            created_at: passkey.created_at,
        }
    }
}

/// An item as its page shows it. Its password and one-time code are
/// fetched only to copy or fill them.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ItemDetail {
    pub id: String,
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub favorite: bool,
    pub has_password: bool,
    pub has_one_time_code: bool,
    /// The names of the item's other fields, in the vault's order (by
    /// name): an identity's name and address, or a login's own extra
    /// fields. Their values are not here; `Device::field` gives one to
    /// copy. A card's own fields are in `card` instead.
    pub fields: Vec<String>,
    /// For a card, its fields.
    pub card: Option<CardDetail>,
    /// A login's passkeys.
    pub passkeys: Vec<PasskeyDetail>,
    pub conflict: bool,
    /// The revision it was read at, which an edit names: an edit of an item
    /// that changed since is refused.
    pub revision: String,
}

/// Who asks for a passkey.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasskeyCaller {
    /// A page, shown by a browser this app trusts to say which page it shows
    /// (Android checked it against the list): the page's origin as Android
    /// gave it, which may end in `/`, and, if the browser made the client
    /// data, its hash, which is then signed as it is.
    Page {
        origin: String,
        client_data_hash: Option<Vec<u8>>,
    },
    /// An app, by the SHA-256 of its signing certificate. Its client data is
    /// made here, with the app's own origin, whatever hash it sent: an app
    /// that is not a trusted browser cannot speak for a site.
    App { certificate_sha256: Vec<u8> },
}

/// Whether the owner is to be verified, as the site asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasskeyVerification {
    /// The site refuses an answer without it.
    Required,
    /// The site wants it: the owner is verified when the phone can.
    Preferred,
    /// The site does not want it.
    Discouraged,
}

impl From<osm_vault_core::passkey::UserVerification> for PasskeyVerification {
    fn from(verification: osm_vault_core::passkey::UserVerification) -> Self {
        use osm_vault_core::passkey::UserVerification;
        match verification {
            UserVerification::Required => Self::Required,
            UserVerification::Preferred => Self::Preferred,
            UserVerification::Discouraged => Self::Discouraged,
        }
    }
}

/// A site's request to make a passkey, as the owner is asked about it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyCreation {
    /// The site it is for.
    pub rp_id: String,
    /// The site's name for itself, as it gave it: not checked.
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub verification: PasskeyVerification,
    /// The logins of that site it may be added to instead of a new one:
    /// those whose address is on the site, or under it, and not in
    /// conflict.
    pub logins: Vec<ItemSummary>,
}

/// A site's request to sign in, as the owner is asked about it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasskeySignIn {
    pub rp_id: String,
    pub verification: PasskeyVerification,
    /// The passkeys the vault holds for the site, of those it takes.
    pub passkeys: Vec<PasskeyChoice>,
}

/// A passkey a site may be signed in to with, and the login it is on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyChoice {
    pub item_id: String,
    pub title: String,
    pub credential_id: String,
    pub user_name: String,
    pub user_display_name: String,
}

/// An edit that met a change made elsewhere, put on top of the item as it
/// is now (see [`Device::rebase_edit`]).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct RebasedEdit {
    /// The owner's changes on top of the item as it is now.
    pub draft: ItemDraft,
    /// The revision the item is at now, which saving the draft names.
    pub revision: String,
    /// What changed elsewhere since the edit began, by field name only.
    pub changed_elsewhere: Vec<String>,
}

/// A card's fields as its page shows them. Its number and security code
/// are not here: only the number's last four digits and whether each is
/// set. `Device::field` gives one to copy, by its name (`Number`,
/// `Security code`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CardDetail {
    pub cardholder: String,
    pub expiry_month: String,
    pub expiry_year: String,
    /// As stored; empty for none.
    pub brand: String,
    pub number_ending: Option<String>,
    pub has_number: bool,
    pub has_security_code: bool,
}

impl CardDetail {
    fn of(item: &osm_vault_core::Item) -> Self {
        use osm_vault_core::card;
        let field = |name: &str| item.custom_fields.get(name).cloned().unwrap_or_default();
        let number = item.custom_fields.get(card::NUMBER);
        Self {
            cardholder: field(card::CARDHOLDER),
            expiry_month: field(card::EXPIRY_MONTH),
            expiry_year: field(card::EXPIRY_YEAR),
            brand: field(card::BRAND),
            number_ending: number.and_then(|number| card::ending(number)),
            has_number: number.is_some(),
            has_security_code: item.custom_fields.contains_key(card::SECURITY_CODE),
        }
    }
}

/// What the owner writes into a card's fields. A number or a security code
/// of `None` keeps what the card has, and an empty one removes it. A brand
/// of `None` is the one a new number names, or else the one the card has.
/// The card's other fields are left as they are.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CardDraft {
    pub cardholder: String,
    pub expiry_month: String,
    pub expiry_year: String,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub security_code: Option<String>,
}

impl CardDraft {
    /// This draft, made from the card as it was at `read`, put on top of
    /// the card as it is now, as [`ItemDraft::rebased`] does.
    fn rebased(self, read: &osm_vault_core::Item, now: &osm_vault_core::Item) -> CardDraft {
        use osm_vault_core::card;
        let field = |item: &osm_vault_core::Item, name: &str| {
            item.custom_fields.get(name).cloned().unwrap_or_default()
        };
        let pick = |mine: String, name: &str| {
            if mine != field(read, name) {
                mine
            } else {
                field(now, name)
            }
        };
        CardDraft {
            cardholder: pick(self.cardholder.trim().to_owned(), card::CARDHOLDER),
            expiry_month: pick(self.expiry_month, card::EXPIRY_MONTH),
            expiry_year: pick(self.expiry_year, card::EXPIRY_YEAR),
            brand: self.brand,
            number: self.number,
            security_code: self.security_code,
        }
    }
}

impl From<CardDraft> for osm_vault_core::card::CardChange {
    fn from(draft: CardDraft) -> Self {
        // Moved, not copied: the change wipes them when it goes.
        Self {
            cardholder: Some(draft.cardholder),
            number: draft.number,
            expiry_month: Some(draft.expiry_month),
            expiry_year: Some(draft.expiry_year),
            security_code: draft.security_code,
            brand: draft.brand,
        }
    }
}

/// What the owner writes into a login, a secure note, or a card. A password
/// or a one-time code secret of `None` keeps what the item has; an empty
/// one removes it. A card's fields are in `card`, for a card only.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemDraft {
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub favorite: bool,
    pub password: Option<String>,
    pub one_time_code_secret: Option<String>,
    pub card: Option<CardDraft>,
}

impl std::fmt::Debug for ItemDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemDraft")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ItemDraft {
    /// Writes the draft over `item`, keeping what the draft leaves alone.
    /// Its values move into the item, which wipes them when it goes; what
    /// is left over is wiped here. (A record cannot wipe itself: the
    /// bindings move its fields out.)
    /// This draft, made from the item as it was at `read`, put on top of
    /// the item as it is now: each field the draft changed takes the
    /// draft's value, and each it left takes the one it has now. A password
    /// or a one-time code secret the draft leaves (`None`) stays as it is
    /// now; none of the item's secrets is put into the draft.
    fn rebased(self, read: &osm_vault_core::Item, now: &osm_vault_core::Item) -> ItemDraft {
        fn pick<T: PartialEq>(mine: T, read: T, now: T) -> T {
            if mine != read {
                mine
            } else {
                now
            }
        }
        let title = pick(self.title.trim(), read.title.as_str(), now.title.as_str()).to_owned();
        let url = pick(self.url.trim(), read.url.as_str(), now.url.as_str()).to_owned();
        ItemDraft {
            title,
            kind: pick(
                self.kind,
                ItemKind::from(read.kind),
                ItemKind::from(now.kind),
            ),
            username: pick(&self.username, &read.username, &now.username).clone(),
            url,
            notes: pick(&self.notes, &read.notes, &now.notes).clone(),
            favorite: pick(self.favorite, read.favorite, now.favorite),
            password: self.password,
            one_time_code_secret: self.one_time_code_secret,
            card: self.card.map(|card| card.rebased(read, now)),
        }
    }

    fn apply_to(self, item: &mut osm_vault_core::Item) {
        let title = Zeroizing::new(self.title);
        let url = Zeroizing::new(self.url);
        item.title = title.trim().to_owned();
        item.kind = self.kind.into();
        item.username = self.username;
        item.url = url.trim().to_owned();
        item.notes = self.notes;
        item.favorite = self.favorite;
        if let Some(password) = self.password {
            item.password = password;
        }
        if let Some(secret) = self.one_time_code_secret {
            let secret = Zeroizing::new(secret);
            item.totp_secret = (!secret.trim().is_empty()).then(|| secret.trim().to_owned());
        }
        if let Some(change) = self.card.map(osm_vault_core::card::CardChange::from) {
            if item.kind == osm_vault_core::ItemKind::Card {
                change.apply_to(item);
            }
        }
    }
}

impl ItemKind {
    /// Whether a phone edits items of this kind.
    fn editable_here(self) -> bool {
        matches!(self, Self::Login | Self::SecureNote | Self::Card)
    }
}

impl From<ItemKind> for osm_vault_core::ItemKind {
    fn from(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => Self::Login,
            ItemKind::SecureNote => Self::SecureNote,
            ItemKind::Identity => Self::Identity,
            ItemKind::Card => Self::Card,
        }
    }
}

/// What a card's number says while it is typed, for the editor: the brand
/// its digits name, and whether it passes the check its last digit is for
/// (Luhn), which catches a mistyped digit. Which brand is stored is decided
/// when the card is saved.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CardNumberCheck {
    pub brand: Option<String>,
    /// It has the length of a card's number, so the check means something.
    pub complete: bool,
    pub passes: bool,
}

#[uniffi::export]
pub fn check_card_number(number: String) -> CardNumberCheck {
    use osm_vault_core::card;
    let number = Zeroizing::new(number);
    CardNumberCheck {
        brand: card::brand_of(&number).map(str::to_owned),
        complete: card::has_card_length(&number),
        passes: card::passes_check(&number),
    }
}

/// Whether a site's request for a passkey is one this app answers, for
/// `caller`, without the vault: read and checked as
/// [`Device::passkey_creation`] (when `creating`) or
/// [`Device::passkey_sign_in`] read and check it. For offering this app, or
/// leaving the request to others, while the vault is locked.
#[uniffi::export]
pub fn check_passkey_request(
    options: String,
    caller: PasskeyCaller,
    creating: bool,
) -> Result<(), MobileError> {
    use osm_vault_core::passkey::{Registering, Signing};
    let asking = runtime::Asking::of(&caller)?;
    if creating {
        Registering::from_options(&options, asking.page.as_ref())?;
    } else {
        Signing::from_options(&options, asking.page.as_ref())?;
    }
    Ok(())
}

/// What the generator makes: `length` characters, at least one of each
/// kind chosen, the look-alikes (l I 1 O 0) left out if asked, as the
/// shared code's `PasswordPolicy` says.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasswordOptions {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_look_alike: bool,
}

/// The generator's choice until the owner makes one: the shared code's.
#[uniffi::export]
pub fn default_password_options() -> PasswordOptions {
    let policy = osm_vault_core::PasswordPolicy::default();
    PasswordOptions {
        length: policy.length as u32,
        lowercase: policy.lowercase,
        uppercase: policy.uppercase,
        digits: policy.digits,
        symbols: policy.symbols,
        avoid_look_alike: policy.avoid_look_alike,
    }
}

/// A new password as `options` asks, from the shared code's generator, as
/// the desktop app makes them; refused with no kind chosen, or a length
/// below the number of kinds or above 1024.
#[uniffi::export]
pub fn generate_password(options: PasswordOptions) -> Result<String, MobileError> {
    let policy = osm_vault_core::PasswordPolicy {
        length: options.length as usize,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
        avoid_look_alike: options.avoid_look_alike,
    };
    osm_vault_core::generate_password(&policy).map_err(Into::into)
}

/// What fills a login form: given only when the owner chose the login, and
/// for a page only when the login is for exactly its origin.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FillCredentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for FillCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FillCredentials { .. }")
    }
}

/// What fills a card form: the card's fields, given only when the owner
/// chose the card. A card belongs to no site, so it may go to any app or
/// page that asks; what it does not have is empty.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CardFill {
    pub cardholder: String,
    /// Its digits only, as the card keeps it.
    pub number: String,
    pub expiry_month: String,
    pub expiry_year: String,
    pub security_code: String,
}

impl std::fmt::Debug for CardFill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CardFill { .. }")
    }
}

/// A login that what a form submitted could be saved into: one that form
/// could be filled with, under the username it had.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SaveCandidate {
    pub id: String,
    pub title: String,
    pub username: String,
    /// The revision it was read at, which the update names.
    pub revision: String,
    /// It has the form's password already: there is nothing to save.
    pub has_this_password: bool,
}

/// One version of an item, as its history shows it: what it changed, by
/// field name, and what it held that may be shown. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HistoryEntry {
    pub revision: String,
    /// It deleted the item.
    pub deleted: bool,
    /// It is one of the item's current versions.
    pub current: bool,
    /// It made the item.
    pub first: bool,
    /// It settled a conflict between versions.
    pub merged: bool,
    pub title: String,
    pub username: String,
    pub url: String,
    /// The fields it changed from the version it followed.
    pub changed: Vec<String>,
    /// The first eight hex digits of the device that made it.
    pub device: String,
    pub this_device: bool,
    /// When it was saved, by that device's clock, in seconds since 1970;
    /// none for a version that does not say.
    pub saved_at: Option<u64>,
}

/// An item deleted on every device that has it, as it was before. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeletedEntry {
    pub id: String,
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub url: String,
    /// The version before the deletion, which a restore brings back.
    pub last: String,
    /// The deletions, which a restore follows.
    pub heads: Vec<String>,
    /// The first eight hex digits of the device that deleted it.
    pub device: String,
    pub this_device: bool,
    /// When, by that device's clock, in seconds since 1970, if it says.
    pub deleted_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SyncState {
    /// Not taking part: the app is in the background, or never went online.
    Offline,
    Idle,
    Syncing,
    Synced,
    Error,
    Removed,
}

/// How this device stands with the others: honest about when it last
/// heard from them, since a phone is often away.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SyncStatus {
    pub state: SyncState,
    /// The other members this device knows an address for.
    pub members: u32,
    /// When a sync last finished, in seconds since the Unix epoch.
    pub last_synced_at: Option<u64>,
    /// Received changes waiting to be verified at the next unlock.
    pub pending: u32,
    pub message: Option<String>,
}

/// One device of a vault, kept in a folder of the app's own.
#[derive(uniffi::Object)]
pub struct Device {
    tokio: tokio::runtime::Runtime,
    inner: Arc<Runtime>,
}

/// The port this device accepts its vault's members on, if it is free.
pub const SYNC_PORT: u16 = 47_820;

#[uniffi::export]
impl Device {
    /// Opens the device whose files are in `folder`, making the folder if
    /// it is new. A vault file there that cannot be opened is reported.
    /// `keystore` seals this device's network key.
    #[uniffi::constructor]
    pub fn open(
        folder: String,
        keystore: Arc<dyn PhoneKeystore>,
    ) -> Result<Arc<Self>, MobileError> {
        Self::open_with_keystore(
            PathBuf::from(folder),
            SYNC_PORT,
            Arc::new(ForeignKeystore(keystore)),
        )
        .map(Arc::new)
    }

    pub fn state(&self) -> DeviceState {
        self.tokio.block_on(self.inner.state())
    }

    pub fn unlock(&self, password: String) -> Result<(), MobileError> {
        let password = Zeroizing::new(password);
        self.tokio.block_on(self.inner.unlock(&password))
    }

    pub fn lock(&self) {
        self.tokio.block_on(self.inner.lock())
    }

    /// Makes `new_password` the one that unlocks this device's vault from
    /// now on, given the current one, while the vault is unlocked. The new
    /// one needs at least 12 characters. A wrong current password changes
    /// nothing. The vault's other devices keep their own passwords.
    pub fn change_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<(), MobileError> {
        let current_password = Zeroizing::new(current_password);
        let new_password = Zeroizing::new(new_password);
        self.tokio
            .block_on(self.inner.change_password(&current_password, &new_password))
    }

    /// Whether an unlock found records taken out of the vault's file or
    /// changed in it (an item, an edit, or a device's keys), and the owner
    /// has not yet confirmed seeing it. What is gone comes back from the
    /// vault's other devices at the next sync. False while locked.
    pub fn rows_changed(&self) -> bool {
        self.tokio.block_on(self.inner.rows_changed())
    }

    /// The owner has seen that records were taken out: stop saying so.
    pub fn confirm_rows_changed(&self) -> Result<(), MobileError> {
        self.tokio.block_on(self.inner.confirm_rows_changed())
    }

    pub fn items(&self) -> Result<Vec<ItemSummary>, MobileError> {
        self.tokio.block_on(self.inner.items())
    }

    /// Which logins hold a weak password or share one, judged now.
    pub fn password_health(&self) -> Result<PasswordHealth, MobileError> {
        self.tokio.block_on(self.inner.password_health())
    }

    pub fn item(&self, id: String) -> Result<ItemDetail, MobileError> {
        self.tokio.block_on(self.inner.item(&id))
    }

    /// The item's password, to copy or fill.
    pub fn password(&self, id: String) -> Result<String, MobileError> {
        self.tokio.block_on(self.inner.password(&id))
    }

    /// The item's current one-time code.
    pub fn one_time_code(&self, id: String) -> Result<String, MobileError> {
        self.tokio.block_on(self.inner.one_time_code(&id))
    }

    /// The value of one of the item's other fields, by a name `fields`
    /// gave, to copy.
    pub fn field(&self, id: String, name: String) -> Result<String, MobileError> {
        self.tokio.block_on(self.inner.field(&id, &name))
    }

    /// Reads and checks a site's request to make a passkey
    /// (`PublicKeyCredentialCreationOptionsJSON`), for [`caller`], and says
    /// what the owner is to be asked. Refused with
    /// [`MobileError::PasskeyRefused`] if it is not one this app answers.
    pub fn passkey_creation(
        &self,
        options: String,
        caller: PasskeyCaller,
    ) -> Result<PasskeyCreation, MobileError> {
        self.tokio
            .block_on(self.inner.passkey_creation(&options, &caller))
    }

    /// Makes the passkey a site asked for, once the owner chose to save it:
    /// on the login `into`, or else on a new login for the site. `verified`
    /// says the owner was verified in this request. Refused with
    /// [`MobileError::PasskeyExists`] if the vault holds one the site says
    /// it has, and with [`MobileError::NotVerified`] if the site requires
    /// verification and the owner was not. Gives the
    /// `RegistrationResponseJSON` for the site.
    pub fn create_passkey(
        &self,
        options: String,
        caller: PasskeyCaller,
        verified: bool,
        into: Option<String>,
    ) -> Result<String, MobileError> {
        self.tokio.block_on(
            self.inner
                .create_passkey(&options, &caller, verified, into.as_deref()),
        )
    }

    /// Reads and checks a site's request to sign in
    /// (`PublicKeyCredentialRequestOptionsJSON`), for [`caller`], and names
    /// the passkeys the vault holds for it.
    pub fn passkey_sign_in(
        &self,
        options: String,
        caller: PasskeyCaller,
    ) -> Result<PasskeySignIn, MobileError> {
        self.tokio
            .block_on(self.inner.passkey_sign_in(&options, &caller))
    }

    /// Signs in to the site with the passkey `credential_id` of the login
    /// `item_id`, which the owner chose. `verified` as for
    /// [`Device::create_passkey`]. Gives the `AuthenticationResponseJSON`
    /// for the site.
    pub fn sign_in_with_passkey(
        &self,
        options: String,
        caller: PasskeyCaller,
        item_id: String,
        credential_id: String,
        verified: bool,
    ) -> Result<String, MobileError> {
        self.tokio.block_on(self.inner.sign_in_with_passkey(
            &options,
            &caller,
            &item_id,
            &credential_id,
            verified,
        ))
    }

    /// The logins `requester` is offered for a form that `asks` for them:
    /// for a page, those saved for its origins; for an app, those the owner
    /// chose for it, and apart from them, the logins of the sites its links
    /// were verified for; for no one named, none. For a code alone, only
    /// logins with a one-time code.
    pub fn offer(&self, requester: Requester, asks: Asks) -> Result<Offer, MobileError> {
        self.tokio.block_on(self.inner.offer(&requester, asks))
    }

    /// What fills the form `requester` shows from the login `id`, of what
    /// it `asks` for: for a page, only a login saved for its origins; for
    /// an app, only one the owner chose for it ([`MobileError::NotChosen`]
    /// otherwise); for no one named, nothing. A form that asks for a code
    /// with the password is filled without one when the login has none.
    pub fn fill(
        &self,
        requester: Requester,
        id: String,
        asks: Asks,
    ) -> Result<Filled, MobileError> {
        self.tokio
            .block_on(self.inner.fill(&requester, &id, asks, false))
    }

    /// As [`Device::fill`], for a login the owner chose on this phone's
    /// screen just now, for an app or a requester that names no one: it may
    /// be any login, and for an app it is remembered, to be offered to that
    /// app from now on. A page is still filled only the logins for its
    /// origins.
    pub fn fill_chosen(
        &self,
        requester: Requester,
        id: String,
        asks: Asks,
    ) -> Result<Filled, MobileError> {
        self.tokio
            .block_on(self.inner.fill(&requester, &id, asks, true))
    }

    /// Every login a form that `asks` could be filled with (for a code
    /// alone, those with a one-time code), for the owner to choose one from
    /// on this phone's screen for an app or a requester that names no one,
    /// with [`Device::fill_chosen`].
    pub fn logins_to_choose(&self, asks: Asks) -> Result<Vec<ItemSummary>, MobileError> {
        self.tokio.block_on(self.inner.logins_to_choose(asks))
    }

    /// The cards a card form is offered: every card not in conflict, for
    /// any app or page.
    pub fn offer_cards(&self) -> Result<Vec<ItemSummary>, MobileError> {
        self.tokio.block_on(self.inner.offer_cards())
    }

    /// The fields of the card the owner chose for a card form, in an app or
    /// on a page; refused for an item that is not a card, and for a card two
    /// devices changed at once, until a computer settles which version is
    /// meant.
    pub fn fill_card(&self, id: String) -> Result<CardFill, MobileError> {
        self.tokio.block_on(self.inner.fill_card(&id))
    }

    /// For saving what a form of `requester` submitted: the logins it could
    /// go into, which are those the form could be filled with (and for a
    /// requester that names no one, none), with the form's `username`
    /// (every one, if the form had none), not in conflict; and whether each
    /// has the form's `password` already.
    pub fn save_candidates_for(
        &self,
        requester: Requester,
        username: String,
        password: String,
    ) -> Result<Vec<SaveCandidate>, MobileError> {
        let password = Zeroizing::new(password);
        self.tokio.block_on(
            self.inner
                .save_candidates_for(&requester, &username, &password),
        )
    }

    /// Changes only the password of the login `id`, as read at `revision`,
    /// to the one a form of `requester` submitted under `username`; refused
    /// unless the login is one of [`Device::save_candidates_for`]
    /// ([`MobileError::NotForThisForm`]), or if it changed since. Online,
    /// it syncs at once.
    pub fn update_saved(
        &self,
        requester: Requester,
        id: String,
        revision: String,
        username: String,
        password: String,
    ) -> Result<(), MobileError> {
        self.tokio.block_on(
            self.inner
                .update_saved(&requester, &id, &revision, &username, password),
        )
    }

    /// Saves what a form of `requester` submitted as a new login titled
    /// `title`, and returns its ID: for a page, saved for its first origin;
    /// for an app, with no address, and remembered for that app; for a
    /// requester that names no one, with no address. Online, it syncs at
    /// once.
    pub fn save_new(
        &self,
        requester: Requester,
        title: String,
        username: String,
        password: String,
    ) -> Result<String, MobileError> {
        self.tokio
            .block_on(self.inner.save_new(&requester, title, username, password))
    }

    /// Adds the logins an earlier build of the app kept as chosen for each
    /// app, by the app's key, to those this device keeps; what is here
    /// already stays. Once it returns, the app may forget its own copy.
    pub fn import_app_choices(
        &self,
        chosen: HashMap<String, Vec<String>>,
    ) -> Result<(), MobileError> {
        self.inner.import_app_choices(chosen)
    }

    /// Makes a login, a secure note, or a card from `draft`, and returns its ID.
    /// Online, it syncs at once.
    pub fn create_item(&self, draft: ItemDraft) -> Result<String, MobileError> {
        self.tokio.block_on(self.inner.create_item(draft))
    }

    /// Writes `draft` over the login or secure note `id`, as read at
    /// `revision`; refused if it changed since, or is in conflict.
    pub fn update_item(
        &self,
        id: String,
        revision: String,
        draft: ItemDraft,
    ) -> Result<(), MobileError> {
        self.tokio
            .block_on(self.inner.update_item(&id, &revision, draft))
    }

    /// For an edit of `id` read at `revision` that [`Device::update_item`]
    /// refused as changed elsewhere: `draft` put on top of the item as it
    /// is now, which the owner sees before saving it again at the revision
    /// given. Nothing is written.
    pub fn rebase_edit(
        &self,
        id: String,
        revision: String,
        draft: ItemDraft,
    ) -> Result<RebasedEdit, MobileError> {
        self.tokio
            .block_on(self.inner.rebase_edit(&id, &revision, draft))
    }

    /// Deletes the login or secure note `id`, as read at `revision`, on
    /// every device. Its earlier versions stay in the vault's history.
    pub fn delete_item(&self, id: String, revision: String) -> Result<(), MobileError> {
        self.tokio.block_on(self.inner.delete_item(&id, &revision))
    }

    /// Removes the passkey `credential_id` of the login `id`, as read at
    /// `revision`, on every device. Its key stays in the login's earlier
    /// versions, and in backups.
    pub fn remove_passkey(
        &self,
        id: String,
        revision: String,
        credential_id: String,
    ) -> Result<(), MobileError> {
        self.tokio
            .block_on(self.inner.remove_passkey(&id, &revision, &credential_id))
    }

    /// Every version of an item, newest first.
    pub fn history(&self, id: String) -> Result<Vec<HistoryEntry>, MobileError> {
        self.tokio.block_on(self.inner.history(&id))
    }

    /// The items deleted, most recently first.
    pub fn deleted_items(&self) -> Result<Vec<DeletedEntry>, MobileError> {
        self.tokio.block_on(self.inner.deleted_items())
    }

    /// Brings back what version `revision` of the login or secure note
    /// `id` held, or the item as it was before it was deleted, following
    /// its current versions `heads`, which the owner was shown. Refused for
    /// an identity or a card, and for an item in conflict. Online, it syncs
    /// at once.
    pub fn restore(
        &self,
        id: String,
        revision: String,
        heads: Vec<String>,
    ) -> Result<(), MobileError> {
        self.tokio
            .block_on(self.inner.restore(&id, &revision, &heads))
    }

    /// Connects to the inviting device from an invitation and returns the
    /// code the owner compares with the one it shows.
    pub fn join_start(&self, invitation: String) -> Result<String, MobileError> {
        let invitation = Zeroizing::new(invitation);
        self.tokio.block_on(self.inner.join_start(&invitation))
    }

    /// After the owner confirmed the codes on both devices: waits for the
    /// vault's devices to enroll this one, and makes its vault with
    /// `password`, unlocked.
    pub fn join_finish(&self, password: String) -> Result<(), MobileError> {
        let password = Zeroizing::new(password);
        self.tokio.block_on(self.inner.join_finish(&password))
    }

    pub fn cancel_join(&self) {
        self.tokio.block_on(self.inner.cancel_join())
    }

    /// Takes part in the vault while the app is in front: accepts the
    /// other members, follows the vault's decisions, and syncs.
    pub fn go_online(&self) -> Result<(), MobileError> {
        self.tokio.block_on(self.inner.go_online())
    }

    /// Stops taking part, as the app goes to the background.
    pub fn go_offline(&self) {
        self.tokio.block_on(self.inner.go_offline())
    }

    /// Syncs with every member it can reach, and says how that went.
    pub fn sync_now(&self) -> Result<SyncStatus, MobileError> {
        self.tokio.block_on(self.inner.sync_now())
    }

    /// For a sync while the app is away from the screen: takes part just
    /// long enough to sync with every member it can reach, then stops,
    /// unless it was taking part already. It never unlocks the vault: a
    /// locked device sends what it wrote, and what arrives waits for the
    /// next unlock.
    pub fn sync_in_background(&self) -> Result<SyncStatus, MobileError> {
        self.tokio.block_on(self.inner.sync_in_background())
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.inner.status()
    }
}

impl Device {
    /// As [`Device::open`] with no keystore, so that the network key is
    /// kept unsealed, accepting members on `port` if it is free, and on any
    /// port otherwise (0 for any).
    pub fn open_listening_on(folder: PathBuf, port: u16) -> Result<Self, MobileError> {
        Self::open_with_keystore(folder, port, Arc::new(osm_vault_peer::NoKeystore))
    }

    /// As [`Device::open_listening_on`], with `keystore` sealing the
    /// network key.
    pub fn open_with_keystore(
        folder: PathBuf,
        port: u16,
        keystore: Arc<dyn osm_vault_peer::Keystore>,
    ) -> Result<Self, MobileError> {
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let inner = tokio.block_on(Runtime::open(folder, port, keystore))?;
        Ok(Self {
            tokio,
            inner: Arc::new(inner),
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.tokio.block_on(self.inner.go_offline());
    }
}
