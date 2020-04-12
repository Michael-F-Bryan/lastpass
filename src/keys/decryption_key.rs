use crate::keys::DecryptionError;
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc, Ecb};
use digest::{Digest, FixedOutput};
use hmac::Hmac;
use sha2::Sha256;
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

#[derive(Copy, Clone)]
pub struct DecryptionKey([u8; DecryptionKey::LEN]);

impl DecryptionKey {
    pub const LEN: usize = crate::keys::KDF_HASH_LEN;

    pub const fn from_raw(key: [u8; DecryptionKey::LEN]) -> Self {
        DecryptionKey(key)
    }

    pub fn calculate(
        username: &str,
        password: &str,
        iterations: usize,
    ) -> Self {
        let username = username.to_lowercase();

        if iterations <= 1 {
            DecryptionKey::sha256(&username, password)
        } else {
            DecryptionKey::pbkdf2(&username, password, iterations)
        }
    }

    fn sha256(username: &str, password: &str) -> Self {
        DecryptionKey::from_raw(
            Sha256::new()
                .chain(username)
                .chain(password)
                .fixed_result()
                .into(),
        )
    }

    fn pbkdf2(username: &str, password: &str, iterations: usize) -> Self {
        let mut key = [0; DecryptionKey::LEN];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            username.as_bytes(),
            iterations,
            &mut key,
        );

        DecryptionKey::from_raw(key)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.is_empty() {
            // Aes256 with Ecb can't un-pad empty inputs
            return Ok(Vec::new());
        }

        let decrypted = if ciphertext.len() >= 33
            && ciphertext.len() % 16 == 1
            && ciphertext.starts_with(b"!")
        {
            let (iv, ciphertext) = ciphertext[1..].split_at(16);

            Cbc::<Aes256, Pkcs7>::new_var(&self.0, &iv)?
                .decrypt_vec(ciphertext)?
        } else {
            Ecb::<Aes256, Pkcs7>::new_var(&self.0, &[])?
                .decrypt_vec(ciphertext)?
        };

        Ok(decrypted)
    }
}

impl Deref for DecryptionKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for DecryptionKey {
    fn as_ref(&self) -> &[u8] { self.deref() }
}

impl<T> PartialEq<T> for DecryptionKey
where
    T: PartialEq<[u8]>,
{
    fn eq(&self, other: &T) -> bool { other == self.as_ref() }
}

impl Debug for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LoginKey").field(&self.as_ref()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_key_with_sha256() {
        let username = "michaelfbryan@gmail.com";
        let password = "My Super Secret Password!";
        let should_be = [
            119, 42, 96, 39, 180, 64, 249, 201, 243, 40, 123, 239, 14, 25, 93,
            74, 103, 166, 140, 169, 64, 6, 69, 107, 237, 61, 212, 24, 15, 196,
            145, 194,
        ];

        let got = DecryptionKey::sha256(username, password);

        assert_eq!(got.as_ref(), &should_be[..]);
    }

    #[test]
    fn decryption_key_with_pbkdf2() {
        let username = "michaelfbryan@gmail.com";
        let password = "My Super Secret Password!";
        let iterations = 100;
        let should_be = &[
            133, 48, 115, 175, 190, 165, 223, 109, 74, 111, 64, 93, 12, 24,
            243, 149, 67, 69, 228, 247, 58, 132, 116, 51, 218, 98, 157, 223,
            214, 187, 133, 190,
        ];

        let got = DecryptionKey::pbkdf2(username, password, iterations);

        assert_eq!(got.as_ref(), &should_be[..]);
    }

    #[test]
    fn decrypt_some_text() {
        // use the key from the blob parser
        let raw =
            "08c9bb2d9b48b39efb774e3fef32a38cb0d46c5c6c75f7f9d65259bfd374e120";
        let mut buffer = [0; DecryptionKey::LEN];
        hex::decode_to_slice(raw, &mut buffer).unwrap();
        let key = DecryptionKey::from_raw(buffer);
        let ciphertext = [
            33, 11, 151, 186, 165, 216, 165, 58, 154, 207, 238, 219, 138, 19,
            26, 178, 141, 91, 241, 31, 28, 69, 189, 39, 5, 10, 161, 76, 57, 10,
            240, 137, 11, 124, 42, 129, 213, 123, 192, 182, 178, 194, 84, 175,
            73, 19, 104, 137, 123,
        ];

        let got = key.decrypt(&ciphertext).unwrap();

        assert_eq!(
            String::from_utf8(got).unwrap(),
            "Example password without folder"
        );
    }
}
