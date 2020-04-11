//! The LastPass API's endpoints.

mod blob;
mod blob_version;
mod iterations;
mod login;
mod logout;

pub use blob::get_blob;
pub use blob_version::get_blob_version;
pub use iterations::iterations;
pub use login::{login, LoginError, TwoFactorLoginRequired};
pub use logout::logout;

use reqwest::{Client, Error, Response};
use serde::Serialize;
use std::fmt::Debug;

/// Typical endpoint errors.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The HTTP client encountered an error.
    #[error("Unable to send the request")]
    HttpClient(#[from] Error),
    /// Unable to parse the XML in the response.
    #[error("Unable to parse the response")]
    XMLParseError(#[from] serde_xml_rs::Error),
    #[error("Unable to parse the response as an integer")]
    BadInteger(
        #[source]
        #[from]
        std::num::ParseIntError,
    ),
}

async fn send<D>(
    client: &Client,
    hostname: &str,
    path: &str,
    data: &D,
) -> Result<Response, Error>
where
    D: Debug + Serialize,
{
    let url = format!("https://{}/{}", hostname, path);

    log::debug!("Sending a request to {}", url);
    log::trace!("Payload: {:#?}", data);
    let response = client
        .post(&url)
        .form(&data)
        .send()
        .await?
        .error_for_status()?;

    log::trace!("Headers: {:#?}", response.headers());

    Ok(response)
}
