//! An unofficial interface to the LastPass API.

#![forbid(unsafe_code)]

pub mod auth;
pub mod endpoints;
mod session;

pub use session::Session;

/// The default user agent to use when communicating with the LastPass server.
pub const DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
