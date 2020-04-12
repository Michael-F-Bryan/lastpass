use crate::{DecryptionError, DecryptionKey, Id};

/// Metadata about an attached file.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Attachment {
    pub id: Id,
    pub parent: Id,
    pub mime_type: String,
    pub storage_key: String,
    pub size: u64,
    pub encrypted_filename: String,
}

impl Attachment {
    pub fn filename(
        &self,
        decryption_key: &DecryptionKey,
    ) -> Result<String, DecryptionError> {
        decryption_key
            .decrypt_base64(&self.encrypted_filename)
            .map(|filename| String::from_utf8(filename).unwrap())
    }
}
