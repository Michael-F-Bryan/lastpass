use crate::{
    Account, Attachment, BlobParseError, DecryptionKey, Id, PrivateKey,
};

/// Information about all accessible accounts and resources.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Blob {
    pub version: u64,
    pub local: bool,
    pub accounts: Vec<Account>,
}

impl Blob {
    pub(crate) fn parse(
        raw: &[u8],
        decryption_key: &DecryptionKey,
        private_key: &PrivateKey,
    ) -> Result<Self, BlobParseError> {
        crate::parser::parse(raw, decryption_key, private_key)
    }

    pub fn attachments(&self) -> impl Iterator<Item = &'_ Attachment> + '_ {
        self.accounts
            .iter()
            .flat_map(|account| account.attachments.iter())
    }

    /// Look up an account by its [`Id`].
    pub fn get_account_by_id(&self, id: &Id) -> Option<&Account> {
        self.accounts.iter().find(|acct| acct.id == *id)
    }
}
