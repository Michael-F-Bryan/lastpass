use reqwest::{Client, Error as ReqwestError};
use serde_derive::{Deserialize, Serialize};

pub async fn get_blob_version(
    client: &Client,
    hostname: &str,
) -> Result<(), BlobError> {
    let data = Data { method: "cli" };
    let response =
        super::send(client, hostname, "login_check.php", &data).await?;

    let body = response.text().await?;
    log::trace!("Response: {}", body);

    let doc: Document = serde_xml_rs::from_str(&body)?;
    log::trace!("Parsed response: {:#?}", doc);

    Ok(())
}

#[derive(Debug, Serialize)]
struct Data<'a> {
    method: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The HTTP client encountered an error.
    #[error("Unable to send the request")]
    HttpClient(#[from] ReqwestError),
    /// Unable to parse the response.
    #[error("Unable to parse the response")]
    ResponseParse(#[from] serde_xml_rs::Error),
}

#[derive(Debug, Deserialize, PartialEq)]
struct Document {}
