use crate::{Attachment, DecryptionError, DecryptionKey, Id};
use url::Url;

/// A single entry, typically a password or address.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Account {
    pub id: Id,
    /// The account's name.
    pub name: String,
    /// Which group the account is in (think of it like a directory).
    pub group: String,
    /// The URL associated with this account.
    pub url: Url,
    /// Any notes that may be attached.
    pub note: String,
    pub note_type: String,
    /// Did the user mark this [`Account`] as a favourite?
    pub favourite: bool,
    /// The associated username.
    pub username: String,
    /// The associated password.
    pub password: String,
    /// Should we prompt for the master password before showing details to the
    /// user?
    pub password_protected: bool,
    /// An encrypted copy of the key used to decode this [`Account`]'s
    /// attachments.
    pub encrypted_attachment_key: String,
    /// Does this account have any [`Attachment`]s?
    pub attachment_present: bool,
    pub last_touch: String,
    pub last_modified: String,
    /// Files which may be attached to this [`Account`].
    pub attachments: Vec<Attachment>,
    pub fields: Vec<Field>,
}

impl Account {
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

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub field_type: String,
    pub name: String,
    pub value: String,
    pub checked: bool,
}
