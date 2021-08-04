use anyhow::Error;
use lastpass::{endpoints, DecryptionKey, LoginKey};
use reqwest::Client;
use structopt::StructOpt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let args = Args::from_args();

    log::debug!("Starting application with {:#?}", args);

    // Create a HTTP client, making sure it remembers cookies so we don't need
    // to supply the PHP session every time
    let client = Client::builder()
        .user_agent(lastpass::DEFAULT_USER_AGENT)
        .cookie_store(true)
        .build()?;

    // How many times should we iterate when generating keys?
    let iterations =
        endpoints::iterations(&client, &args.host, &args.username).await?;

    // create a key which can be used to log in
    let login_key =
        LoginKey::calculate(&args.username, &args.password, iterations);

    let decryption_key =
        DecryptionKey::calculate(&args.username, &args.password, iterations);
    // send a login request and initialise our user session
    let session = endpoints::login(
        &client,
        &args.host,
        &args.username,
        &login_key,
        &decryption_key,
        iterations,
        args.trusted_id(),
    )
    .await?;

    log::info!("Logged in as {} {:#?}", args.username, session);

    // The vault has a version number which gets incremented every time a change
    // is made. A real application avoid downloading a new snapshot of the vault
    // (a potentially expensive request) by using this number to see whether a
    // cached version is still valid.
    let vault_version =
        endpoints::get_vault_version(&client, &args.host).await?;
    log::info!("Current vault version: {}", vault_version);

    // We need our master decryption key to decrypt the vault (note: this is
    // separate to the login key)
    let decryption_key =
        DecryptionKey::calculate(&args.username, &args.password, iterations);

    // grab a snapshot of the vault
    let vault = endpoints::get_vault(
        &client,
        &args.host,
        &decryption_key,
        &session.private_key,
    )
    .await?;

    // and dump it to stdout... this will be really really verbose
    log::debug!("{:#?}", vault);

    // now lets print out the contents of every attachment

    for account in &vault.accounts {
        log::info!(
            "{}\\{} => {:?}",
            account.group,
            account.name,
            account.password,
        );

        if account.attachments.is_empty() {
            continue;
        }

        for attachment in &account.attachments {
            // each "account" (password, secure note, address, etc.) uses its
            // own key for encrypting attachments. An encrypted version is
            // attached to the account, and can only be accessed if you have
            // the master decryption key
            let attachment_key = account.attachment_key(&decryption_key)?;

            // print out the attachment's name and some info about it
            let filename = attachment.filename(&attachment_key)?;
            log::info!(
                "*** {} - {} ({} bytes) ***",
                account.name,
                filename,
                attachment.size
            );
            log::debug!("{:#?}", attachment);

            // actually fetch the attachment
            let payload = endpoints::load_attachment(
                &client,
                &args.host,
                &session.token,
                &attachment.storage_key,
                &attachment_key,
            )
            .await?;

            // try to print it out if it's text, otherwise print it as hex
            match std::str::from_utf8(&payload) {
                Ok(payload) => log::info!("{}", payload),
                Err(_) => log::info!("{:?}", hex::encode(payload)),
            }
        }
    }

    log::info!("Logging out");
    endpoints::logout(&client, &args.host, &session.token).await?;

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
