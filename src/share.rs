use crate::{DecryptionKey, Id};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub(crate) struct Share {
    pub id: Id,
    pub name: String,
    pub key: DecryptionKey,
    pub readonly: bool,
}
