//! The LastPass API's endpoints.

use reqwest::{Client, Error as ReqwestError};
use serde_derive::{Deserialize, Serialize};

pub async fn logout(
    client: &Client,
    hostname: &str,
    token: &str,
) -> Result<(), ReqwestError> {
    let url = format!("https://{}/logout.php", hostname);
    let data = LogoutData {
        method: "cli",
        noredirect: 1,
        token,
    };

    log::debug!("Sending a logout request to {}", url);
    log::trace!("Payload: {:#?}", data);
    client
        .post(&url)
        .form(&data)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct LogoutData<'a> {
    method: &'a str,
    noredirect: usize,
    token: &'a str,
}

pub async fn login(
    client: &Client,
    hostname: &str,
    username: &str,
    hash: &str,
    iterations: usize,
) -> Result<(), LoginError> {
    let url = format!("https://{}/login.php", hostname);
    let data = LoginData {
        xml: 2,
        username,
        hash,
        iterations,
        includeprivatekeyenc: 1,
        method: "cli",
        outofbandsupported: 1,
        trusted_id: None,
    };

    log::debug!("Sending a login request to {}", url);
    log::trace!("Payload: {:#?}", data);
    let response = client
        .post(&url)
        .form(&data)
        .send()
        .await?
        .error_for_status()?;

    log::trace!("Headers: {:#?}", response.headers());

    let body = response.text().await?;
    log::trace!("Response: {}", body);

    Ok(())
}

// append_post(args, "xml", "2");
// append_post(args, "username", user_lower);
// append_post(args, "hash", hash);
// append_post(args, "iterations", iters);
// append_post(args, "includeprivatekeyenc", "1");
// append_post(args, "method", "cli");
// append_post(args, "outofbandsupported", "1");
// if (trusted_id)
// 	append_post(args, "uuid", trusted_id);

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct LoginData<'a> {
    xml: usize,
    username: &'a str,
    hash: &'a str,
    iterations: usize,
    includeprivatekeyenc: usize,
    method: &'a str,
    outofbandsupported: usize,
    trusted_id: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("Unable to send the login request")]
    HttpClient(
        #[source]
        #[from]
        ReqwestError,
    ),
}
