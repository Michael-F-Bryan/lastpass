use crate::Id;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub(crate) struct Share {
    pub id: Id,
    pub name: String,
    pub key: Vec<u8>,
    pub readonly: bool,
}
