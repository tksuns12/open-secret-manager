use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    #[default]
    Login,
    SecureNote,
    Identity,
    Card,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub custom_fields: BTreeMap<String, String>,
    pub tags: Vec<String>,
    pub favorite: bool,
}

impl Item {
    /// The fields this item has changed from `before`, by name: `title`,
    /// `type`, `username`, `password`, `website`, `one-time code`, `notes`,
    /// `other fields`, `tags`, `favorite`. Names only, never values.
    pub fn changed_from(&self, before: &Item) -> Vec<&'static str> {
        [
            (before.title != self.title, "title"),
            (before.kind != self.kind, "type"),
            (before.username != self.username, "username"),
            (before.password != self.password, "password"),
            (before.url != self.url, "website"),
            (before.totp_secret != self.totp_secret, "one-time code"),
            (before.notes != self.notes, "notes"),
            (before.custom_fields != self.custom_fields, "other fields"),
            (before.tags != self.tags, "tags"),
            (before.favorite != self.favorite, "favorite"),
        ]
        .into_iter()
        .filter_map(|(changed, name)| changed.then_some(name))
        .collect()
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.totp_secret.zeroize();
        for (mut name, mut value) in std::mem::take(&mut self.custom_fields) {
            name.zeroize();
            value.zeroize();
        }
        for tag in &mut self.tags {
            tag.zeroize();
        }
        self.tags.clear();
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("favorite", &self.favorite)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl Default for Item {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: String::new(),
            kind: ItemKind::Login,
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: None,
            custom_fields: BTreeMap::new(),
            tags: Vec::new(),
            favorite: false,
        }
    }
}

impl Item {
    pub fn new(title: impl Into<String>) -> Self {
        let mut item = Self::default();
        item.title = title.into();
        item
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.id.is_empty() {
            return Err(crate::Error::InvalidItem("id must not be empty".into()));
        }
        if self.id.len() > 128 {
            return Err(crate::Error::InvalidItem("id is too long".into()));
        }
        if self.title.trim().is_empty() {
            return Err(crate::Error::InvalidItem("title must not be empty".into()));
        }
        if self
            .totp_secret
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(crate::Error::InvalidItem(
                "TOTP secret must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionInfo {
    pub item_id: String,
    pub revision: String,
    /// Sorted revision IDs this revision supersedes; more than one for a
    /// conflict resolution.
    pub parents: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub item: Item,
    pub revision: String,
    /// The item has concurrent heads. `item` and `revision` are then one
    /// deterministic live head, and changes must go through `Vault::resolve`.
    pub conflict: bool,
}

impl fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultItem")
            .field("item", &self.item)
            .field("revision", &self.revision)
            .field("conflict", &self.conflict)
            .finish()
    }
}

/// Result of storing a received revision for later processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// Stored durably; it will be verified when processed.
    Staged,
    /// Already stored, staged, or quarantined.
    Duplicate,
}

/// Result of processing staged revisions after unlock.
#[derive(Debug, Default)]
pub struct IngressReport {
    pub applied: usize,
    pub quarantined: usize,
    /// Failed verification and were discarded.
    pub rejected: usize,
    /// Still waiting for a parent.
    pub pending: usize,
    /// Why the first rejected revision failed.
    pub first_rejection: Option<crate::Error>,
}

/// What a fork into a new trust domain carried over and what it left in the
/// source vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForkReport {
    /// Items carried over.
    pub items: usize,
    /// Items carried with more than one version, still to be resolved.
    pub conflicts: usize,
    /// Revisions held for the owner's review, not carried.
    pub held_left_behind: usize,
    /// Received revisions not yet verified, not carried.
    pub staged_left_behind: usize,
}

/// What a backup holds, as read back by the device that wrote it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackupCheck {
    /// Items with any revision, deleted ones included.
    pub items: usize,
    /// Revisions of those items: every version, kept as history.
    pub revisions: usize,
    /// Revisions held for the owner's review.
    pub held: usize,
}

/// A revision held because its author is not an authorized device. It was
/// encrypted with the vault key but is not part of the item's history until
/// the owner accepts it.
#[derive(Clone, PartialEq, Eq)]
pub struct QuarantinedRevision {
    pub revision: String,
    pub item_id: String,
    pub author_device_id: [u8; 16],
    /// The author is a device this vault knows, in practice one that was
    /// removed, and the revision verifies under its key. Accepting or
    /// rejecting it then settles it on every device; otherwise accepting
    /// re-authors the content and rejecting only drops it here.
    pub known_author: bool,
    /// Parents named by the author.
    pub parents: Vec<String>,
    /// `None` when the held revision deletes the item.
    pub item: Option<Item>,
}

impl fmt::Debug for QuarantinedRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuarantinedRevision")
            .field("revision", &self.revision)
            .field("item_id", &self.item_id)
            .field("author_device_id", &self.author_device_id)
            .field("known_author", &self.known_author)
            .field("parents", &self.parents)
            .field("deleted", &self.item.is_none())
            .finish()
    }
}

/// One current head of an item, for reviewing a conflict.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemVersion {
    pub revision: String,
    pub author_device_id: [u8; 16],
    /// `None` when this head deletes the item.
    pub item: Option<Item>,
}

impl fmt::Debug for ItemVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemVersion")
            .field("revision", &self.revision)
            .field("author_device_id", &self.author_device_id)
            .field("deleted", &self.item.is_none())
            .finish()
    }
}

/// One stored version of an item, for its history.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryVersion {
    pub revision: String,
    /// The versions it followed: none for the first, one for an edit,
    /// several where it settled a conflict.
    pub parents: Vec<String>,
    pub author_device_id: [u8; 16],
    /// `None` when this version deletes the item.
    pub item: Option<Item>,
    /// It is one of the item's current versions.
    pub current: bool,
    /// What it changed from the version it followed, by field (see
    /// [`Item::changed_from`]); nothing for the first version or a
    /// deletion.
    pub changed: Vec<&'static str>,
}

impl fmt::Debug for HistoryVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryVersion")
            .field("revision", &self.revision)
            .field("parents", &self.parents)
            .field("author_device_id", &self.author_device_id)
            .field("deleted", &self.item.is_none())
            .field("current", &self.current)
            .field("changed", &self.changed)
            .finish()
    }
}

/// An item that every one of its current versions deletes.
#[derive(Clone, PartialEq, Eq)]
pub struct DeletedItem {
    pub item_id: String,
    /// The version the deletion followed, which a restore brings back.
    pub last: ItemVersion,
    /// The deletions that are its current versions, which a restore names.
    pub heads: Vec<String>,
    /// Who deleted it: the author of its newest deletion.
    pub deleted_by: [u8; 16],
}

impl fmt::Debug for DeletedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeletedItem")
            .field("item_id", &self.item_id)
            .field("last", &self.last)
            .field("heads", &self.heads)
            .field("deleted_by", &self.deleted_by)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub kind: ItemKind,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    pub revision: String,
    pub conflict: bool,
}

impl fmt::Debug for ItemSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("favorite", &self.favorite)
            .field("contents", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("conflict", &self.conflict)
            .finish()
    }
}

impl From<VaultItem> for ItemSummary {
    fn from(value: VaultItem) -> Self {
        let VaultItem {
            item,
            revision,
            conflict,
        } = value;
        Self {
            id: item.id.clone(),
            title: item.title.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
            favorite: item.favorite,
            revision,
            conflict,
        }
    }
}

/// What filling a login into a page releases, and nothing else of the item.
#[derive(Clone, PartialEq, Eq)]
pub struct FillCredentials {
    pub username: String,
    pub password: String,
}

impl Drop for FillCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl fmt::Debug for FillCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FillCredentials([REDACTED])")
    }
}

/// One unlock of a vault, from the moment it is unlocked until it locks.
/// Unlocking again starts another, so a decision the owner made during one
/// unlock can be told apart from the next. It names the unlock and is not a
/// secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnlockSession([u8; 16]);

impl UnlockSession {
    pub(crate) fn new(id: [u8; 16]) -> Self {
        Self(id)
    }
}

impl fmt::Display for UnlockSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for UnlockSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnlockSession({self})")
    }
}

impl std::str::FromStr for UnlockSession {
    type Err = crate::Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || crate::Error::InvalidItem("invalid unlock session".into());
        let mut id = [0_u8; 16];
        if text.len() != 2 * id.len() || !text.is_ascii() {
            return Err(invalid());
        }
        for (byte, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportFormat {
    BitwardenJson,
    ChromeCsv,
    FirefoxCsv,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportWarning {
    pub row: usize,
    pub message: String,
}

pub struct ImportPreview {
    pub(crate) items: Vec<Item>,
    pub(crate) warnings: Vec<ImportWarning>,
    pub(crate) confirmation_id: [u8; 16],
}

impl ImportPreview {
    pub fn items(&self) -> &[Item] {
        &self.items
    }
    pub fn warnings(&self) -> &[ImportWarning] {
        &self.warnings
    }
    pub fn valid_count(&self) -> usize {
        self.items.len()
    }
}

impl fmt::Debug for ImportPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportPreview")
            .field("valid_count", &self.items.len())
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}
