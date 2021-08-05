//! An unofficial interface to the LastPass API.

#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod account;
mod app;
mod attachment;
pub mod endpoints;
mod id;
mod keys;
mod parser;
mod session;
mod share;
mod utils;
mod vault;

pub use account::Account;
pub use account::Field;
pub use attachment::Attachment;
pub use id::Id;
pub use keys::{DecryptionError, DecryptionKey, LoginKey, PrivateKey};
pub use parser::VaultParseError;
pub use session::Session;
pub use vault::Vault;

// these guys aren't fully completed yet
pub(crate) use app::App;
pub(crate) use share::Share;

/// The default user agent to use when communicating with the LastPass server.
pub const DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
