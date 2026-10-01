#![forbid(unsafe_code)]

mod crypto;
mod error;
mod import;
mod model;
mod storage;
mod util;

pub use crypto::{epoch_key_check, RecoveryKey};
pub use error::{Error, Result};
pub use import::preview_import;
pub use model::{
    ForkReport, ImportFormat, ImportPreview, ImportWarning, IngressReport, Item, ItemKind,
    ItemSummary, ItemVersion, PasswordPolicy, QuarantinedRevision, RevisionInfo, StageOutcome,
    VaultItem,
};
pub use storage::{
    verify_pairing_signature, EncryptedRevision, EnrollmentMaterial, PendingDevice, Vault,
    CONTROL_SIGNATURE_DOMAIN, PAIRING_SIGNATURE_DOMAIN,
};
pub use util::{generate_password, totp_code};

impl Vault {
    /// Generates the current TOTP code for an unlocked vault item.
    pub fn item_totp_code(&self, item_id: &str, unix_time: u64) -> Result<String> {
        let item = self.get(item_id)?.item;
        let secret = item
            .totp_secret
            .as_deref()
            .ok_or_else(|| Error::InvalidItem("item has no TOTP secret".into()))?;
        totp_code(secret, unix_time)
    }

    pub fn confirm_import(&mut self, preview: ImportPreview) -> Result<Vec<RevisionInfo>> {
        if preview.confirmation_id == [0; 16] {
            return Err(Error::InvalidImport("invalid confirmation".into()));
        }
        self.put_items_atomic(preview.items)
    }
}

#[cfg(test)]
mod tests;
