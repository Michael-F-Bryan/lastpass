use digest::Digest;
use hmac::Hmac;
use sha2::Sha256;
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

/// A hex-encoded hash of the username and password.
#[derive(Copy, Clone)]
pub struct LoginKey([u8; LoginKey::LEN]);

impl LoginKey {
    pub const LEN: usize = crate::keys::KDF_HASH_LEN * 2;

    /// Calculate a new [`LoginKey`].
    pub fn calculate(
        username: &str,
        password: &str,
        iterations: usize,
    ) -> Self {
        let username = username.to_lowercase();

        if iterations <= 1 {
            LoginKey::sha256(&username, password)
        } else {
            LoginKey::pbkdf2(&username, password, iterations)
        }
    }

    /// Get the key's hex-encoded representation.
    pub fn as_hex(&self) -> &str {
        std::str::from_utf8(&self.0)
            .expect("The calculation process ensures this is a hex string")
    }

    fn sha256(username: &str, password: &str) -> Self {
        let first_pass = Sha256::new().chain(username).chain(password).result();
        let first_pass_hex = hex::encode(&first_pass);

        let second_pass = Sha256::new()
            .chain(&first_pass_hex)
            .chain(password)
            .result();

        LoginKey::from_bytes(&second_pass)
    }

    fn pbkdf2(username: &str, password: &str, iterations: usize) -> Self {
        // the first rearranges the password (maintaining length), salting it
        // with the username
        let mut first_pass = [0; crate::keys::KDF_HASH_LEN];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            username.as_bytes(),
            iterations,
            &mut first_pass,
        );

        // we then hash the previous key, salting with the password
        // previous key
        let mut key = [0; crate::keys::KDF_HASH_LEN];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            &first_pass,
            password.as_bytes(),
            1,
            &mut key,
        );

        LoginKey::from_bytes(&key)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len() * 2, LoginKey::LEN);

        let mut key = [0; LoginKey::LEN];
        hex::encode_to_slice(bytes, &mut key)
            .expect("the assert guarantees we've got the right length");

        LoginKey(key)
    }
}

impl Deref for LoginKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for LoginKey {
    fn as_ref(&self) -> &[u8] { self.deref() }
}

impl PartialEq for LoginKey {
    fn eq(&self, other: &LoginKey) -> bool { self.0[..] == other.0[..] }
}
impl<T> PartialEq<T> for LoginKey
where
    T: PartialEq<[u8]>,
{
    fn eq(&self, other: &T) -> bool { other == self.as_ref() }
}

impl Debug for LoginKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LoginKey").field(&"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_key_with_sha256() {
        let username = "michaelfbryan@gmail.com";
        let password = "My Super Secret Password!";
        let should_be =
            LoginKey(*b"b8a31d9784fa9a263d0e7a0d866b70612687f7067733126d74ccde02d3bab494");

        let got = LoginKey::sha256(username, password);

        assert_eq!(got, should_be);
    }

    #[test]
    fn login_key_with_pbkdf2() {
        let username = "michaelfbryan@gmail.com";
        let password = "My Super Secret Password!";
        let iterations = 100;
        let should_be =
            LoginKey(*b"f93111b2fb6699de187ef8307aa84b1e9fdabf4a46cb821e83e507a95c3f7c97");

        let got = LoginKey::pbkdf2(username, password, iterations);

        assert_eq!(got, should_be);
    }
}
