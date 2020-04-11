use crate::keys::PrivateKey;

/// A user session.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Session {
    pub uid: String,
    pub token: String,
    pub private_key: PrivateKey,
    pub session_id: String,
}
