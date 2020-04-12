use std::{
    fmt::{self, Debug, Formatter},
    str::FromStr,
};

/// A private key that can be used to decrypt items in the password vault.
#[derive(Clone, PartialEq)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    pub fn new<V: Into<Vec<u8>>>(key: V) -> Self { PrivateKey(key.into()) }
}

impl FromStr for PrivateKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<PrivateKey, Self::Err> {
        hex::decode(s).map(PrivateKey)
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateKey").field(&"<redacted>").finish()
    }
}
