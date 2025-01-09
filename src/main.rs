pub mod oidc;
pub mod utils;

use authify::oidc::callback_listener;
use authify::oidc::oidc_client::OidcClient;
use clap::Parser;
use serde_json::to_string_pretty;

#[derive(Parser, Debug)]
#[command(version, about = "Authify: An OIDC client CLI tool to login and get access tokens", long_about = None)]

pub struct Args {
    /// The issuer URL of the OIDC provider
    #[arg(short = 'i', long)]
    pub issuer: String,

    /// The client ID registered with the OIDC provider
    #[arg(short = 'c', long)]
    pub client_id: String,

    /// The client secret registered with the OIDC provider
    #[arg(short = 's', long)]
    pub client_secret: String,

    /// The redirect URL for the OIDC provider (default: http://127.0.0.1:3030/callback)
    #[arg(short = 'r', long, default_value = "http://127.0.0.1:3030/callback")]
    pub redirect_url: String,

    /// The scope of the access request (default: openid)
    #[arg(short = 'o', long, default_value = "openid")]
    pub scope: String,

    /// An optional state parameter for the request
    #[arg(short = 't', long)]
    pub state: Option<String>,

    /// An optional refresh token to renew the access token
    #[arg(short = 'f', long)]
    pub refresh_token: Option<String>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Args::parse();

    let mut client = OidcClient::new(
        &args.issuer,
        &args.client_id,
        &args.client_secret,
        &args.redirect_url,
        args.scope.split_whitespace().map(String::from).collect(),
        args.state,
    )?;

    let wells = client.get_well_knowns();
    println!("Well-Known Endpoints: {}", to_string_pretty(&wells)?);

    if let Some(refresh_token) = &args.refresh_token {
        handle_refresh_token(&mut client, refresh_token)?;
    } else {
        handle_authorization_code_flow(&mut client)?;
    }

    Ok(())
}

fn handle_refresh_token(
    client: &mut OidcClient,
    refresh_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_endpoint_response = client.refresh_token(refresh_token)?;
    println!(
        "Token Endpoint Response: {}",
        to_string_pretty(&token_endpoint_response)?
    );

    if let Ok(user_info) = client.get_user_info(&token_endpoint_response.access_token) {
        println!("User Info: {}", to_string_pretty(&user_info)?);
    } else {
        eprintln!("Failed to get user info");
    }
    Ok(())
}

fn handle_authorization_code_flow(
    client: &mut OidcClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = client.build_authorization_url()?;
    println!("Authorization URL: {}", auth_url.clone());

    if open::that(auth_url).is_err() {
        eprintln!("Failed to open auth URL in browser");
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let code = runtime.block_on(async {
        match callback_listener::listen().await {
            Ok(code) => Ok(code),
            Err(e) => {
                eprintln!("Failed to get auth code: {}", e);
                Err(e as Box<dyn std::error::Error>)
            }
        }
    })?;
    println!("Authorization code: {}", code.clone());

    let token_endpoint_response = client.get_token(code.as_str())?;
    println!(
        "Token Endpoint Response: {}",
        to_string_pretty(&token_endpoint_response)?
    );

    if let Ok(user_info) = client.get_user_info(&token_endpoint_response.access_token) {
        println!("User Info: {}", to_string_pretty(&user_info)?);
    } else {
        eprintln!("Failed to get user info");
    }

    Ok(())
}
