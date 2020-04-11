use anyhow::Error;
use lastpass::{
    endpoints,
    keys::{DecryptionKey, LoginKey},
};
use reqwest::Client;
use structopt::StructOpt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let args = Args::from_args();
    log::debug!("Starting application with {:#?}", args);

    let client = Client::builder()
        .user_agent(lastpass::DEFAULT_USER_AGENT)
        .cookie_store(true)
        .build()?;

    let iterations =
        endpoints::iterations(&client, &args.host, &args.username).await?;

    let login_key =
        LoginKey::calculate(&args.username, &args.password, iterations);

    let session = endpoints::login(
        &client,
        &args.host,
        &args.username,
        &login_key,
        iterations,
        args.trusted_id(),
    )
    .await?;

    log::info!("Logged in as {}", args.username);

    let blob_version = endpoints::get_blob_version(&client, &args.host).await?;
    log::info!("Current blob version: {}", blob_version);

    let decryption_key =
        DecryptionKey::calculate(&args.username, &args.password, iterations);

    endpoints::get_blob(
        &client,
        &args.host,
        &decryption_key,
        &session.private_key,
    )
    .await?;

    Ok(())
}

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(
        long = "host",
        default_value = "lastpass.com",
        help = "The LastPass server's hostname"
    )]
    host: String,
    #[structopt(short = "u", long = "username", help = "Your username")]
    username: String,
    #[structopt(
        short = "t",
        long = "trusted-id",
        help = "The token from your 2FA provider"
    )]
    trusted_id: Option<String>,
    #[structopt(short = "p", long = "password", help = "Your master password")]
    password: String,
}

impl Args {
    pub fn trusted_id(&self) -> Option<&str> {
        match self.trusted_id {
            Some(ref id) => Some(&id),
            None => None,
        }
    }
}
