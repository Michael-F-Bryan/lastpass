use std::{
    fmt::{self, Debug, Formatter},
    str::Utf8Error,
};

use rsa::{
    pkcs8::{self, FromPrivateKey},
    PaddingScheme, RsaPrivateKey,
};
use sha1::Sha1;

use crate::{utils::cipher_unbase64, DecryptionError, DecryptionKey};

/// A private key that can be used to decrypt items in the password vault.
#[derive(Clone, PartialEq)]
pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.is_empty() {
            // If there's no input, there's nothing to decrypt
            return Ok(Vec::new());
        }

        self.0
            .decrypt(PaddingScheme::new_oaep::<Sha1>(), ciphertext)
            .map_err(|e| DecryptionError::RsaDecryptionFailed(e))
    }

    pub fn from_encrypted_der(
        encrypted_der: &str,
        decryption_key: DecryptionKey,
    ) -> Result<PrivateKey, PrivateKeyParseError> {
        const LASTPASS_PRIV_KEY_START: &str = "LastPassPrivateKey<";
        const LASTPASS_PRIV_KEY_END: &str = ">LastPassPrivateKey";
        let encrypted_key_bytes = if encrypted_der.bytes().nth(0) == Some(b'!')
        {
            cipher_unbase64(encrypted_der)
                .ok_or(PrivateKeyParseError::GenericParseError)?
        } else {
            let mut encrypted_key_bytes =
                Vec::<u8>::with_capacity(encrypted_der.len() + 16 + 1);
            encrypted_key_bytes.push(b'!');
            encrypted_key_bytes
                .extend_from_slice(&decryption_key.get_key_bytes()[0..=15]);

            encrypted_key_bytes.extend_from_slice(&hex::decode(encrypted_der)?);

            encrypted_key_bytes
        };
        let decrypted_key_bytes =
            decryption_key.decrypt(&encrypted_key_bytes)?;
        let decrypted_private_key =
            std::str::from_utf8(&decrypted_key_bytes)?.to_string();

        let decrypted_private_key = decrypted_private_key
            .strip_prefix(LASTPASS_PRIV_KEY_START)
            .ok_or(PrivateKeyParseError::GenericParseError)?
            .strip_suffix(LASTPASS_PRIV_KEY_END)
            .ok_or(PrivateKeyParseError::GenericParseError)?;

        rsa::RsaPrivateKey::from_pkcs8_der(&hex::decode(decrypted_private_key)?)
            .map(|key| PrivateKey(key))
            .map_err(|e| PrivateKeyParseError::Pkcs8Error(e))
    }

    pub fn from_rsa(key: rsa::RsaPrivateKey) -> PrivateKey {
        PrivateKey(key)
    }
}

/// Used to indicate the private key parse error
/// This is different from general vault parse error
/// because it has many more varied errors
#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyParseError {
    #[error("Decryption failed")]
    DecryptionFailed(#[from] DecryptionError),
    #[error("The string did not parse into hex")]
    HexError(#[from] hex::FromHexError),
    #[error("The string did not parse from valid base64")]
    Base64Error(#[from] base64::DecodeError),
    #[error("The binary blob did not form a valid key")]
    Pkcs8Error(#[from] pkcs8::Error),
    #[error("The encrypted key did not parse into valid utf8")]
    Utf8Error(#[from] Utf8Error),
    /// Only use this when there is no other error valid
    #[error("The encrypted key did not parse correctly")]
    GenericParseError,
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateKey").field(&"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_encoded_private_key() {
        //! Assert key parses without panicing
        const PRIVATE_KEY_HEX: &str =
            include_str!("../vault_with_complex_accounts_key.txt");

        const DECRYPTION_KEY: &str =
            "6613202bda71fa40fcb6253ba0b462466c118a0d779fcca5993c226150403dfb";
        let decryption_key = DecryptionKey::from_hex(DECRYPTION_KEY).unwrap();

        PrivateKey::from_encrypted_der(PRIVATE_KEY_HEX, decryption_key)
            .unwrap();
    }
}
