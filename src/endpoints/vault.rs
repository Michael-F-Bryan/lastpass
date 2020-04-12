use crate::{
    keys::{DecryptionKey, PrivateKey},
    Vault, VaultParseError,
};
use reqwest::{Client, Error as ReqwestError};
use serde_derive::Serialize;

const LASTPASS_CLI_VERSION: &str = "1.3.3.15.g8767b5e";

/// Fetch the latest vault snapshot from LastPass.
pub async fn get_vault(
    client: &Client,
    hostname: &str,
    decryption_key: &DecryptionKey,
    private_key: &PrivateKey,
) -> Result<Vault, VaultError> {
    let data = Data {
        mobile: 1,
        request_src: "cli",
        // I'm not sure why lastpass-cli used its version number instead of a
        // bool here, but \_(ツ)_/¯
        has_plugin: LASTPASS_CLI_VERSION,
    };

    let body = super::send(client, hostname, "getaccts.php", &data)
        .await?
        .bytes()
        .await?;

    Vault::parse(&body, decryption_key, private_key).map_err(VaultError::Parse)
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
pub enum VaultError {
    /// The HTTP client encountered an error.
    #[error("Unable to send the request")]
    HttpClient(#[from] ReqwestError),
    #[error("Unable to parse the vault")]
    Parse(#[from] VaultParseError),
}
