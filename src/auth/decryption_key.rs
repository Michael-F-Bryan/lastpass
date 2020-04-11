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
    pub const LEN: usize = crate::auth::KDF_HASH_LEN;

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
        DecryptionKey(
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

        DecryptionKey(key)
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
        let iterations = 100100;
        let should_be = &[
            33, 99, 98, 155, 40, 16, 32, 184, 58, 246, 13, 238, 149, 190, 210,
            114, 33, 208, 0, 14, 26, 142, 168, 119, 181, 104, 227, 104, 85, 2,
            117, 249,
        ];

        let got = DecryptionKey::pbkdf2(username, password, iterations);

        assert_eq!(got.as_ref(), &should_be[..]);
    }
}
