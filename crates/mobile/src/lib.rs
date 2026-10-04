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
//! one-time code to copy or fill. What crosses cannot be wiped there.
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
    #[error("that is not an https origin")]
    InvalidOrigin,
    #[error("that login is not for this page")]
    NotForThisPage,
    #[error("that item is not a login")]
    NotALogin,
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
    pub conflict: bool,
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
