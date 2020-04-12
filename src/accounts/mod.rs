//! Account management.

mod blob_parser;

pub use blob_parser::BlobParseError;

use crate::keys::DecryptionKey;
use std::{ops::Deref, str::FromStr};

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
    ) -> Result<Self, BlobParseError> {
        blob_parser::parse(raw, decryption_key)
    }
}

/// A single entry, typically a password or address.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Account {
    pub id: Id,
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
    pub id: Id,
    pub parent: Id,
    pub mime_type: String,
    pub storage_key: String,
    pub size: u64,
    pub filename: String,
}

/// A unique resource identifier.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct Id(String);

impl<S: Into<String>> From<S> for Id {
    fn from(other: S) -> Id { Id(other.into()) }
}

impl Deref for Id {
    type Target = str;

    fn deref(&self) -> &str { &self.0 }
}

impl FromStr for Id {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Id, Self::Err> { Ok(Id::from(s)) }
}
