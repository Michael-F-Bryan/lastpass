//! An unofficial interface to the LastPass API.

#![forbid(unsafe_code)]

pub mod endpoints;

pub const DEFAULT_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
