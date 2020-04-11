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
struct Document {
    #[serde(rename = "$value")]
    response: BlobResponse,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename = "ok")]
pub struct BlobResponse {
    uid: String,
    #[serde(rename = "sessionid")]
    session_id: String,
    token: String,
    #[serde(rename = "accts_version")]
    accounts_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_blob_version_okay() {
        let src = include_str!("blob_version_get_okay.xml");
        let should_be = Document {
            response: BlobResponse {
                uid: String::from("111111111"),
                session_id: String::from("SESSION-ID"),
                token: String::from("BASE64ENCODEDTOKEN="),
                accounts_version: 198,
            },
        };

        let got: Document = serde_xml_rs::from_str(src).unwrap();

        assert_eq!(got, should_be);
    }
}
