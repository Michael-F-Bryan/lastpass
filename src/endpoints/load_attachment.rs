use crate::keys::DecryptionKey;
use reqwest::{Client, Error as ReqwestError};
use serde_derive::Serialize;

pub async fn load_attachment(
    client: &Client,
    hostname: &str,
    token: &str,
    storage_key: &str,
    decryption_key: &DecryptionKey,
) -> Result<Vec<u8>, LoadAttachmentError> {
    let data = Data { token, storage_key };

    let response =
        super::send(client, hostname, "getattach.php", &data).await?;

    let ciphertext: String = response.text().await?;
    let data = decryption_key.decrypt_base64(&ciphertext)?;

    // not only was the ciphertext in base64, the attachment body was too
    base64::decode(data).map_err(LoadAttachmentError::Decode)
}

#[derive(Debug, Serialize)]
struct Data<'a> {
    token: &'a str,
    #[serde(rename = "getattach")]
    storage_key: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadAttachmentError {
    /// The HTTP client encountered an error.
    #[error("Unable to send the request")]
    HttpClient(#[from] ReqwestError),
    #[error("Unable to decrypt the payload")]
    Decrypt(#[from] crate::DecryptionError),
    #[error("Unable to decode the decrypted attachment")]
    Decode(#[from] base64::DecodeError),
}
