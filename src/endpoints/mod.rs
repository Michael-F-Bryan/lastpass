//! The LastPass API's endpoints.

mod blob;
mod iterations;
mod login;
mod logout;

pub use blob::get_blob_version;
pub use iterations::{iterations, IterationsError};
pub use login::{login, LoginError, TwoFactorLoginRequired};
pub use logout::logout;

use reqwest::{Client, Error, Response};
use serde::Serialize;
use std::fmt::Debug;

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
