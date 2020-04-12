use crate::{
    accounts::{Blob, BlobParseError},
    keys::{DecryptionKey, PrivateKey},
};
use reqwest::{Client, Error as ReqwestError};
use serde_derive::Serialize;

const LASTPASS_CLI_VERSION: &str = "1.3.3.15.g8767b5e";

/// Fetch the latest account snapshot from LastPass.
pub async fn get_blob(
    client: &Client,
    hostname: &str,
    decryption_key: &DecryptionKey,
    private_key: &PrivateKey,
) -> Result<Blob, BlobError> {
    let data = Data {
        mobile: 1,
        request_src: "cli",
        // I'm not sure why we use the lastpass-cli version number instead of a
        // bool here, but \_(ツ)_/¯
        has_plugin: LASTPASS_CLI_VERSION,
    };

    let body = super::send(client, hostname, "getaccts.php", &data)
        .await?
        .bytes()
        .await?;

    Blob::parse(&body, decryption_key, private_key).map_err(BlobError::Parse)
}

#[derive(Debug, Serialize)]
struct Data<'a> {
    mobile: usize,
    #[serde(rename = "requestsrc")]
    request_src: &'a str,
    #[serde(rename = "hasplugin")]
    has_plugin: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The HTTP client encountered an error.
    #[error("Unable to send the request")]
    HttpClient(#[from] ReqwestError),
    #[error("Unable to parse the blob")]
    Parse(#[from] BlobParseError),
}
