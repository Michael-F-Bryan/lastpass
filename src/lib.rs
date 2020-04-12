//! An unofficial interface to the LastPass API.

#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod accounts;
pub mod endpoints;
pub mod keys;
mod session;

pub use accounts::{Account, App, Attachment, Blob, BlobParseError, Id, Share};
pub use session::Session;

/// The default user agent to use when communicating with the LastPass server.
pub const DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
