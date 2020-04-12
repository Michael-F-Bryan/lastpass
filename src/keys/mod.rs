//! Key management.

mod decryption_key;
mod login_key;
mod private_key;

const SHA256_LEN: usize =
    <<sha2::Sha256 as digest::FixedOutput>::OutputSize as typenum::marker_traits::Unsigned>::USIZE;
const KDF_HASH_LEN: usize = SHA256_LEN;

pub use decryption_key::DecryptionKey;
pub use login_key::LoginKey;
pub use private_key::PrivateKey;

/// Errors that are returned when decryption fails.
#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("The key isn't valid")]
    InvalidKey(#[from] block_modes::InvalidKeyIvLength),
    #[error("Decryption failed")]
    DecryptionFailed(#[from] block_modes::BlockModeError),
}
