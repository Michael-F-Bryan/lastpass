use digest::{Digest, FixedOutput};
use hmac::Hmac;
use sha2::Sha256;
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

#[derive(Copy, Clone)]
pub struct LoginKey([u8; LoginKey::LEN]);

impl LoginKey {
    pub const LEN: usize = crate::auth::KDF_HASH_LEN * 2;

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

    fn sha256(username: &str, password: &str) -> LoginKey {
        let first_pass =
            Sha256::new().chain(username).chain(password).fixed_result();
        let first_pass_hex = hex::encode(&first_pass);

        let second_pass = Sha256::new()
            .chain(&first_pass_hex)
            .chain(password)
            .fixed_result();
        let hash = hex::encode(second_pass);

        assert_eq!(hash.len(), LoginKey::LEN);
        let mut key = [0; LoginKey::LEN];

        for (i, byte) in hash.bytes().enumerate() {
            key[i] = byte;
        }

        LoginKey(key)
    }

    fn pbkdf2(username: &str, password: &str, iterations: usize) -> Self {
        let mut first_pass = [0; LoginKey::LEN];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            username.as_bytes(),
            iterations,
            &mut first_pass,
        );

        let mut key = [0; LoginKey::LEN];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            username.as_bytes(),
            password.as_bytes(),
            1,
            &mut key,
        );

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

impl<T> PartialEq<T> for LoginKey
where
    T: PartialEq<[u8]>,
{
    fn eq(&self, other: &T) -> bool { other == self.as_ref() }
}

impl Debug for LoginKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LoginKey").field(&self.as_ref()).finish()
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
            b"b8a31d9784fa9a263d0e7a0d866b70612687f7067733126d74ccde02d3bab494";

        let got = LoginKey::sha256(username, password);

        assert_eq!(got.as_ref(), &should_be[..]);
    }

    #[test]
    fn login_key_with_pbkdf2() {
        let username = "michaelfbryan@gmail.com";
        let password = "My Super Secret Password!";
        let iterations = 100100;
        let should_be =
            b"9a1a77150b9745a0bf3188aea87071571cbfa11f98b1236eb04073b791dd2f47";

        let got = LoginKey::pbkdf2(username, password, iterations);

        assert_eq!(got.as_ref(), &should_be[..]);
    }
}
