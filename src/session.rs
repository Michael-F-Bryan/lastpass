#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Session {
    pub uid: String,
    pub token: String,
    pub encoded_private_key: String,
    pub session_id: String,
}
