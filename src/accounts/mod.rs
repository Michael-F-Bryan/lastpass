//! Account management.

mod blob_parser;

pub use blob_parser::BlobParseError;

use crate::keys::{DecryptionKey, PrivateKey};

/// Information about all accessible accounts and resources.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Blob {
    pub version: u64,
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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Account {
    id: String,
    name: String,
    group: String,
    url: String,
    note: String,
    note_type: String,
    favourite: bool,
    username: String,
    password: String,
    password_protected: bool,
    attachment_key: String,
    attachment_present: bool,
    last_touch: String,
    last_modified: String,
}

impl Account {
    pub fn parse(
        raw: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<Self, BlobParseError> {
        blob_parser::parse_account(raw, decryption_key)
    }
}
