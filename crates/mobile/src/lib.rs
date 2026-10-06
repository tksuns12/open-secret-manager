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
//! On a phone the owner creates, edits, deletes, and restores logins and
//! secure notes, and saves what another app's login form submitted; identities and
//! cards are read there and edited on a computer, as are conflicts between
//! devices.
//!
//! This crate's own code has no `unsafe`; the foreign function interface
//! that UniFFI generates around it is made of it.

#![deny(unsafe_code)]

mod runtime;

use std::{path::PathBuf, sync::Arc};

use zeroize::Zeroizing;

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
    #[error("{reason}")]
    InvalidItem { reason: String },
    /// The item changed since it was read, here or on another device.
    #[error("the item changed since it was opened")]
    ChangedElsewhere,
    /// Two devices changed the item at once; a computer resolves that.
    #[error("two devices changed the item at once")]
    InConflict,
    /// Identities and cards are edited on a computer.
    #[error("that kind of item is edited on a computer")]
    NotEditableHere,
    // Not `message`: in Kotlin every exception has one already.
    #[error("{reason}")]
    Network { reason: String },
    #[error("{reason}")]
    Storage { reason: String },
}

impl From<osm_vault_core::Error> for MobileError {
    fn from(error: osm_vault_core::Error) -> Self {
        use osm_vault_core::Error;
        match error {
            Error::Locked => Self::Locked,
            Error::InvalidCredentials => Self::InvalidCredentials,
            Error::NotFound => Self::NotFound,
            Error::OriginMismatch => Self::NotForThisPage,
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
    /// name): a card's number and security code, an identity's name and
    /// address, or a login's own extra fields. Their values are not here;
    /// `Device::field` gives one to copy.
    pub fields: Vec<String>,
    pub conflict: bool,
    /// The revision it was read at, which an edit names: an edit of an item
    /// that changed since is refused.
    pub revision: String,
}

/// What the owner writes into a login or a secure note. A password or a
/// one-time code secret of `None` keeps what the item has; an empty one
/// removes it.
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
    }
}

impl ItemKind {
    /// Whether a phone edits items of this kind.
    fn editable_here(self) -> bool {
        matches!(self, Self::Login | Self::SecureNote)
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

/// A new password of `length` characters with letters, digits, and
/// symbols, from the shared code's generator, as the desktop app makes
/// them; a length it does not allow is refused.
#[uniffi::export]
pub fn generate_password(length: u32) -> Result<String, MobileError> {
    let policy = osm_vault_core::PasswordPolicy {
        length: length as usize,
        ..osm_vault_core::PasswordPolicy::default()
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
    #[uniffi::constructor]
    pub fn open(folder: String) -> Result<Arc<Self>, MobileError> {
        Self::open_listening_on(PathBuf::from(folder), SYNC_PORT).map(Arc::new)
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

    /// The logins for a page of `origin` (`https://host` or
    /// `https://host:port`), by the one rule the desktop's browser fill
    /// uses: HTTPS, the exact host, and the exact port.
    pub fn logins_for_web(&self, origin: String) -> Result<Vec<ItemSummary>, MobileError> {
        self.tokio.block_on(self.inner.logins_for_web(&origin))
    }

    /// The user name and password of the login the owner chose for a page
    /// of `origin`; refused unless the login is for exactly that origin.
    pub fn fill_for_web(&self, id: String, origin: String) -> Result<FillCredentials, MobileError> {
        self.tokio.block_on(self.inner.fill_for_web(&id, &origin))
    }

    /// The user name and password of the login the owner chose for an app,
    /// which has no origin to check: only after the owner picked it for
    /// that app.
    pub fn fill_for_app(&self, id: String) -> Result<FillCredentials, MobileError> {
        self.tokio.block_on(self.inner.fill_for_app(&id))
    }

    /// For a form that asks for a one-time code: of the logins in `ids`,
    /// which are those the form could be filled with, the ones that have a
    /// one-time code. Unknown IDs are skipped.
    pub fn with_one_time_codes(&self, ids: Vec<String>) -> Result<Vec<ItemSummary>, MobileError> {
        self.tokio.block_on(self.inner.with_one_time_codes(&ids))
    }

    /// The current one-time code of the login the owner chose for a page of
    /// `origin`; refused unless the login is for exactly that origin. For
    /// an app, [`Device::one_time_code`] gives it.
    pub fn one_time_code_for_web(&self, id: String, origin: String) -> Result<String, MobileError> {
        self.tokio
            .block_on(self.inner.one_time_code_for_web(&id, &origin))
    }

    /// Makes a login or a secure note from `draft`, and returns its ID.
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

    /// Deletes the login or secure note `id`, as read at `revision`, on
    /// every device. Its earlier versions stay in the vault's history.
    pub fn delete_item(&self, id: String, revision: String) -> Result<(), MobileError> {
        self.tokio.block_on(self.inner.delete_item(&id, &revision))
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

    /// For saving what a login form submitted: of the logins in `ids`,
    /// which are those the form could be filled with, the ones with the
    /// form's `username` (every one, if the form had none), and whether each
    /// has the form's `password` already. Logins in conflict are left out.
    pub fn save_candidates(
        &self,
        ids: Vec<String>,
        username: String,
        password: String,
    ) -> Result<Vec<SaveCandidate>, MobileError> {
        let password = Zeroizing::new(password);
        self.tokio
            .block_on(self.inner.save_candidates(&ids, &username, &password))
    }

    /// Changes only the password of the login `id`, as read at `revision`;
    /// refused if it changed since, or is in conflict. Online, it syncs at
    /// once.
    pub fn update_password(
        &self,
        id: String,
        revision: String,
        password: String,
    ) -> Result<(), MobileError> {
        self.tokio
            .block_on(self.inner.update_password(&id, &revision, password))
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
    /// As [`Device::open`], accepting members on `port` if it is free, and
    /// on any port otherwise (0 for any).
    pub fn open_listening_on(folder: PathBuf, port: u16) -> Result<Self, MobileError> {
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let inner = tokio.block_on(Runtime::open(folder, port))?;
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
