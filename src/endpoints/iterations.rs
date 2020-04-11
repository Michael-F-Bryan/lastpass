use super::EndpointError;
use reqwest::Client;
use serde_derive::{Deserialize, Serialize};

/// Get the number of iterations to use when encrypting the user's password.
pub async fn iterations(
    client: &Client,
    hostname: &str,
    username: &str,
) -> Result<usize, EndpointError> {
    let url = format!("https://{}/iterations.php", hostname);
    let data = IterationsData { email: username };

    log::debug!("Sending an iterations request to {}", url);
    log::trace!("Payload: {:#?}", data);

    let response = client
        .post(&url)
        .form(&data)
        .send()
        .await?
        .error_for_status()?;

    log::trace!("Response Headers: {:#?}", response.headers());

    let body = response.text().await?;
    log::trace!("Response Body: {}", body);

    body.trim().parse().map_err(Into::into)
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct IterationsData<'a> {
    email: &'a str,
}
