use crate::keys::PrivateKey;

/// Information about the current user session.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Session {
    /// The session ID.
    pub uid: String,
    /// A token that can is used to access attachments.
    pub token: String,
    /// A private key used to decode shared items.
    pub private_key: PrivateKey,
    /// The PHP session ID.
    pub session_id: String,
}
