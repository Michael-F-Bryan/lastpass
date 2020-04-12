use crate::{Attachment, BlobParseError, DecryptionError, DecryptionKey, Id};
use url::Url;

/// A single entry, typically a password or address.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Account {
    pub id: Id,
    pub name: String,
    pub group: String,
    pub url: Url,
    pub note: String,
    pub note_type: String,
    pub favourite: bool,
    pub username: String,
    pub password: String,
    /// Should we prompt for the master password before showing details to the
    /// user?
    pub password_protected: bool,
    pub encrypted_attachment_key: String,
    pub attachment_present: bool,
    pub last_touch: String,
    pub last_modified: String,
    pub attachments: Vec<Attachment>,
}

impl Account {
    pub fn parse(
        raw: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<Self, BlobParseError> {
        crate::parser::parse_account(raw, decryption_key)
    }

    /// Get the key used to work with this [`Account`]'s attachments.
    pub fn attachment_key(
        &self,
        decryption_key: &DecryptionKey,
    ) -> Result<DecryptionKey, DecryptionError> {
        let hex =
            decryption_key.decrypt_base64(&self.encrypted_attachment_key)?;
        let key = DecryptionKey::from_hex(&hex)?;

        Ok(key)
    }
}
