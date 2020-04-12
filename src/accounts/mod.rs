//! Account management.

mod blob_parser;

pub use blob_parser::BlobParseError;

use crate::keys::{DecryptionKey, PrivateKey};

/// Information about all accessible accounts and resources.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Blob {
    pub version: u64,
    pub accounts: Vec<Account>,
}

impl Blob {
    pub fn parse(
        raw: &[u8],
        decryption_key: &DecryptionKey,
        private_key: &PrivateKey,
    ) -> Result<Self, BlobParseError> {
        blob_parser::parse(raw, decryption_key, private_key)
    }
}

/// A single entry, typically a password or address.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Account {
    pub id: String,
    pub name: String,
    pub group: String,
    pub url: String,
    pub note: String,
    pub note_type: String,
    pub favourite: bool,
    pub username: String,
    pub password: String,
    /// Should we prompt for the master password before showing details to the
    /// user?
    pub password_protected: bool,
    pub attachment_key: String,
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
        blob_parser::parse_account(raw, decryption_key)
    }
}

/// Metadata about an attached file.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Attachment {
    pub id: String,
    pub parent: String,
    pub mime_type: String,
    pub storage_key: String,
    pub size: u64,
    pub filename: String,
}
