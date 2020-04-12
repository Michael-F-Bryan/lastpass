use anyhow::Error;
use lastpass::{endpoints, DecryptionKey, LoginKey};
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

    log::info!(
        "Logged in as {} with session id: {}",
        args.username,
        session.session_id
    );

    let blob_version = endpoints::get_blob_version(&client, &args.host).await?;
    log::info!("Current blob version: {}", blob_version);

    let decryption_key =
        DecryptionKey::calculate(&args.username, &args.password, iterations);

    let blob = endpoints::get_blob(
        &client,
        &args.host,
        &decryption_key,
        &session.private_key,
    )
    .await?;

    log::info!("{:#?}", blob);

    for account in &blob.accounts {
        if !account.attachments.is_empty() {
            log::info!("{}", account.name);
        }

        for attachment in &account.attachments {
            log::info!(
                "*** {} ({} bytes) ***",
                attachment.encrypted_filename,
                attachment.size
            );

            let attachment_key = account.attachment_key(&decryption_key)?;

            let payload = endpoints::load_attachment(
                &client,
                &args.host,
                &session.token,
                &attachment.storage_key,
                &attachment_key,
            )
            .await?;

            match std::str::from_utf8(&payload) {
                Ok(payload) => log::debug!("{}", payload),
                Err(_) => log::debug!("{:?}", hex::encode(payload)),
            }
        }
    }

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
