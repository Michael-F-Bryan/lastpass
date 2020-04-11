//! Account management.

use crate::keys::{DecryptionKey, PrivateKey};

#[derive(Debug, Clone, PartialEq)]
pub struct Blob {}

impl Blob {
    pub fn parse(
        _raw: &[u8],
        _decryption_key: &DecryptionKey,
        _private_key: &PrivateKey,
    ) -> Result<Blob, BlobParseError> {
        unimplemented!()
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BlobParseError {}
