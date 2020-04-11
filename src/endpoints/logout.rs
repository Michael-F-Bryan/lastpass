
use reqwest::{Client, Error as ReqwestError};
use serde_derive::{Deserialize, Serialize};

/// Tell the server to invalidate a user's session, logging them out.
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
