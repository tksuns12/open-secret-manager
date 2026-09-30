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
    pub parent_revision: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub item: Item,
    pub revision: String,
}

impl fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultItem")
            .field("item", &self.item)
            .field("revision", &self.revision)
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
}

impl fmt::Debug for ItemSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("favorite", &self.favorite)
            .field("contents", &"[REDACTED]")
            .field("revision", &self.revision)
            .finish()
    }
}

impl From<VaultItem> for ItemSummary {
    fn from(value: VaultItem) -> Self {
        let VaultItem { item, revision } = value;
        Self {
            id: item.id.clone(),
            title: item.title.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
            favorite: item.favorite,
            revision,
        }
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
