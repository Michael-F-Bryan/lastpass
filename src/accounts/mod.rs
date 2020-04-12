//! Account management.

mod blob_parser;

pub use blob_parser::BlobParseError;

use crate::keys::{DecryptionKey, PrivateKey};
use std::{ops::Deref, str::FromStr};
use url::Url;

/// Information about all accessible accounts and resources.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Blob {
    pub version: u64,
    pub local: bool,
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

    pub fn attachments(&self) -> impl Iterator<Item = &'_ Attachment> + '_ {
        self.accounts
            .iter()
            .flat_map(|account| account.attachments.iter())
    }

    pub fn account_by_id(&self, id: &Id) -> Option<&Account> {
        self.accounts.iter().find(|acct| acct.id == *id)
    }
}

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
    pub encrypted_filename: String,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Share {
    pub id: Id,
    pub name: String,
    pub key: Vec<u8>,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct App {
    pub id: Id,
    pub app_name: String,
    pub extra: String,
    pub name: String,
    pub group: String,
    pub last_touch: String,
    pub password_protected: bool,
    pub favourite: bool,
    pub window_title: String,
    pub window_info: String,
    pub exe_version: String,
    pub autologin: bool,
    pub warn_version: String,
    pub exe_hash: String,
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
