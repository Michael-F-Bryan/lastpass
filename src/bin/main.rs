use anyhow::Error;
use reqwest::Client;

use lastpass::endpoints;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let client = Client::builder()
        .user_agent(lastpass::DEFAULT_USER_AGENT)
        .cookie_store(true)
        .build()?;

    endpoints::login(
        &client,
        "lastpass.com",
        "michaelfbryan@gmail.com",
        "asdf",
        0,
    )
    .await?;
    Ok(())
}
