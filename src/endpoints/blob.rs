use super::EndpointError;
use reqwest::Client;
use serde_derive::{Deserialize, Serialize};

pub async fn get_blob(
    client: &Client,
    hostname: &str,
) -> Result<(), EndpointError> {
    unimplemented!()
}
