use crate::{DecryptionError, DecryptionKey, Id};

/// Metadata about an attached file.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Attachment {
    pub id: Id,
    /// The ID of the parent [`crate::Account`].
    pub parent: Id,
    /// The file's mimetype.
    pub mime_type: String,
    /// An opaque string which is used by the backend to find the correct
    /// version of an attached file.
    ///
    /// Note: uploading a new version will change the storage key, but the
    /// attachment's ID stays the same.
    pub storage_key: String,
    /// The size of the attachment, in bytes.
    pub size: u64,
    /// The attachment's filename, encrypted using the account's
    /// `attachment_key`.
    pub encrypted_filename: String,
}

impl Attachment {
    pub fn filename(
        &self,
        attachment_key: &DecryptionKey,
    ) -> Result<String, DecryptionError> {
        attachment_key
            .decrypt_base64(&self.encrypted_filename)
            .map(|filename| String::from_utf8(filename).unwrap())
    }
}
