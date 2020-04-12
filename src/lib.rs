//! An unofficial interface to the LastPass API.

#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod accounts;
pub mod endpoints;
mod keys;
mod session;

pub use accounts::{Account, Attachment, Blob, BlobParseError, Id};
pub use keys::{DecryptionError, DecryptionKey, LoginKey, PrivateKey};
pub use session::Session;

/// The default user agent to use when communicating with the LastPass server.
pub const DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
