use reqwest::{Client, Error as ReqwestError};
use serde_derive::Serialize;

/// Tell the server to invalidate a user's session, logging them out.
pub async fn logout(
    client: &Client,
    hostname: &str,
    token: &str,
) -> Result<(), ReqwestError> {
    let data = Data {
        method: "cli",
        noredirect: 1,
        token,
    };
    super::send(client, hostname, "logout.php", &data).await?;

    Ok(())
}

#[derive(Debug, Serialize)]
struct Data<'a> {
    method: &'a str,
    noredirect: usize,
    token: &'a str,
}
