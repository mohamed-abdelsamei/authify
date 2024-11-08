use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str;

use crate::oidc::jwt_client;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WellKnowns {
    auth_url: String,
    token_url: String,
    user_info_url: String,
    jwks_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenEndpointResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcAgent {
    /// The issuer URL for the OIDC provider.
    issuer: String,
    /// The client ID for this OIDC client.
    client_id: String,
    /// The client secret for this OIDC client.
    client_secret: String,
    /// The redirect URL for the OIDC flow.
    redirect_url: String,
    /// The scope requested for the OIDC flow.
    scope: Vec<String>,
    /// The well-known OIDC configuration endpoints.
    well_knowns: WellKnowns,

    state: Option<String>,
}
impl OidcAgent {
    pub fn get_well_knowns(&self) -> &WellKnowns {
        &self.well_knowns
    }

    fn fetch_well_knowns_from_issuer(&self) -> Result<WellKnowns, Box<dyn std::error::Error>> {
        let well_known_url = format!("{}/.well-known/openid-configuration", self.issuer);
        self.fetch_well_knowns_from_custom_url(&well_known_url)
    }

    fn fetch_well_knowns_from_custom_url(
        &self,
        url: &str,
    ) -> Result<WellKnowns, Box<dyn std::error::Error>> {
        let response = reqwest::blocking::get(url)?;

        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch well-known configuration: {}",
                response.status()
            )
            .into());
        }

        let json: Value = response.json()?;

        Ok(WellKnowns {
            auth_url: json["authorization_endpoint"]
                .as_str()
                .ok_or("Missing authorization_endpoint")?
                .to_string(),
            token_url: json["token_endpoint"]
                .as_str()
                .ok_or("Missing token_endpoint")?
                .to_string(),
            user_info_url: json["userinfo_endpoint"]
                .as_str()
                .ok_or("Missing userinfo_endpoint")?
                .to_string(),
            jwks_url: json["jwks_uri"]
                .as_str()
                .ok_or("Missing jwks_uri")?
                .to_string(),
        })
    }

    pub fn build_authorization_url(&self) -> String {
        let scope = self.scope.join(" ");
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.well_knowns.auth_url,
            self.client_id,
            self.redirect_url,
            scope,
            self.state.as_deref().unwrap_or("")
        )
    }

    pub fn build_token_url(&self) -> String {
        self.well_knowns.token_url.clone()
    }

    pub fn get_token(
        &self,
        code: &str,
    ) -> Result<TokenEndpointResponse, Box<dyn std::error::Error>> {
        let token_url = self.build_token_url();

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_url),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];

        let client = reqwest::blocking::Client::new();
        let response = client.post(&token_url).form(&params).send()?;

        if !response.status().is_success() {
            return Err(format!("Token request failed with status: {}", response.status()).into());
        }

        let json: Value = response.json()?;
        println!("{:?}", json.clone());

        match jwt_client::decode_jwt_without_verification(
            &json["id_token"].as_str().unwrap().to_string(),
        ) {
            Ok((header, payload)) => {
                println!("Header: {:#?}", header);
                println!("Payload: {:#?}", payload);
            }
            Err(_) => todo!(),
        };

        return Ok(TokenEndpointResponse {
            access_token: json["access_token"]
                .as_str()
                .ok_or_else(|| "Token type not found in response")?
                .to_string(),
            token_type: json["token_type"]
                .as_str()
                .ok_or_else(|| "Token type not found in response")?
                .to_string(),
            expires_in: json["expires_in"]
                .as_u64()
                .ok_or_else(|| "Expires in not found in response")?,
            refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
            scope: json["scope"].as_str().map(|s| s.to_string()),
            id_token: json["id_token"].as_str().map(|s| s.to_string()),
        });
    }

    pub fn handle_error(&self, error: Box<dyn std::error::Error>) -> Result<(), String> {
        eprintln!("An error occurred during the OIDC flow: {}", error);
        Err(error.to_string())
    }

    pub fn new(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
        scope: Vec<String>,
        state: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut agent = Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_url: redirect_url.to_string(),
            scope,
            well_knowns: WellKnowns {
                auth_url: String::new(),
                token_url: String::new(),
                user_info_url: String::new(),
                jwks_url: String::new(),
            },
            state: state,
        };

        agent.well_knowns = agent.fetch_well_knowns_from_issuer()?;

        Ok(agent)
    }
}
