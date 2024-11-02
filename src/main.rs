pub mod oidc;

use clap::Parser;
use iden::oidc::callback_listener;

/// Command-line arguments for the OIDC client application
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The issuer URL for the OIDC provider
    #[arg(long)]
    issuer: String,
    /// The client ID for this OIDC client
    #[arg(long)]
    client_id: String,
    /// The client secret for this OIDC client
    #[arg(long)]
    client_secret: String,
    /// The redirect URL for the OIDC flow
    #[arg(long, default_value = "http://127.0.0.1:3030/callback")]
    redirect_url: String,
    /// The scopes requested for the OIDC flow
    #[arg(long)]
    scopes: Vec<String>,
    /// The state for the OIDC flow`         `
    #[arg(long)]
    state: Option<String>,
}

fn main() {
    let args: Args = Args::parse();

    println!("Issuer: {}", args.issuer);
    println!("Client ID: {}", args.client_id);
    println!("Client Secret: {}", args.client_secret);
    println!("Redirect URL: {}", args.redirect_url);

    let agent = match oidc::oidc_agent::OidcAgent::new(
        &args.issuer,
        &args.client_id,
        &args.client_secret,
        &args.redirect_url,
        args.scopes,
        args.state,
    ) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("Failed to create OidcAgent: {}", e);
            return; // or handle the error appropriately
        }
    };

    // check  well-knowns
    let wells = agent.get_well_knowns();
    print!("{:?}", wells);

    // build auth url
    let auth_url = agent.build_authorization_url();
    println!("Auth URL: {}", auth_url);

    // open auth_url in browser
    match open::that(auth_url) {
        Ok(_) => println!("Opened auth URL in browser"),
        Err(e) => eprintln!("Failed to open auth URL in browser: {}", e),
    }

    // start http server to listed to callback url
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let code = runtime
        .block_on(async { callback_listener::listen().await })
        .expect("Failed to get auth code");
    println!("Authorization code: {}", code.clone());
    let token = agent.get_token(code.as_str());
    match token {
        Ok(token) => println!("Token: {:?}", token),
        Err(e) => eprintln!("Failed to get token: {}", e),
    }
}
