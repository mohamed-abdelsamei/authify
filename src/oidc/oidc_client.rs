use rand::Rng;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};

use crate::oidc::jwt_client;

#[derive(Debug)]
pub enum OidcError {
    NetworkError(reqwest::Error),
    InvalidResponse(String),
    MissingField(String),
    DecodingError(String),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OidcError::NetworkError(e) => write!(f, "Network error: {}", e),
            OidcError::InvalidResponse(s) => write!(f, "Invalid response: {}", s),
            OidcError::MissingField(s) => write!(f, "Missing field: {}", s),
            OidcError::DecodingError(s) => write!(f, "Decoding error: {}", s),
        }
    }
}

impl std::error::Error for OidcError {}

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
pub struct OidcClient {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scope: Vec<String>,
    well_knowns: WellKnowns,
    state: Option<String>,
}

impl OidcClient {
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

    pub fn build_authorization_url(&mut self) -> Result<String, OidcError> {
        let scope = self.scope.join(" ");
        let state = self.generate_state();

        self.state = Some(state.clone());

        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.well_knowns.auth_url, self.client_id, self.redirect_url, scope, state
        );

        url.push_str("&access_type=offline");

        Ok(url)
    }

    fn generate_state(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    }

    pub fn build_token_url(&self) -> String {
        self.well_knowns.token_url.clone()
    }

    pub fn get_token(&self, code: &str) -> Result<TokenEndpointResponse, OidcError> {
        let token_url = self.build_token_url();

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_url),
            ("client_id", &self.client_id),
        ];

        params.push(("client_secret", &self.client_secret));

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&token_url)
            .form(&params)
            .send()
            .map_err(OidcError::NetworkError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            println!(
                "Token request failed with status: {:?}, body: {}",
                status, error_body
            );
            return Err(OidcError::InvalidResponse(format!(
                "Token request failed with status: {}, body: {}",
                status, error_body
            )));
        }

        let json: Value = response.json().map_err(OidcError::NetworkError)?;

        let id_token = json["id_token"].as_str();
        if let Some(id_token) = id_token {
            match jwt_client::decode_jwt_without_verification(id_token) {
                Ok((header, payload)) => {
                    println!("Header: {:?}", to_string_pretty(&header).unwrap());
                    println!("Payload: {:?}", to_string_pretty(&payload).unwrap());
                }
                Err(e) => eprintln!("Failed to decode JWT: {}", e),
            };
        }

        Ok(TokenEndpointResponse {
            access_token: json["access_token"]
                .as_str()
                .ok_or_else(|| OidcError::MissingField("access_token".to_string()))?
                .to_string(),
            token_type: json["token_type"]
                .as_str()
                .ok_or_else(|| OidcError::MissingField("token_type".to_string()))?
                .to_string(),
            expires_in: json["expires_in"]
                .as_u64()
                .ok_or_else(|| OidcError::MissingField("expires_in".to_string()))?,
            refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
            scope: json["scope"].as_str().map(|s| s.to_string()),
            id_token: json["id_token"].as_str().map(|s| s.to_string()),
        })
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenEndpointResponse, OidcError> {
        let token_url = self.build_token_url();

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
        ];

        params.push(("client_secret", &self.client_secret));

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&token_url)
            .form(&params)
            .send()
            .map_err(OidcError::NetworkError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            println!(
                "Token refresh request failed with status: {:?}, body: {}",
                status, error_body
            );
            return Err(OidcError::InvalidResponse(format!(
                "Token refresh request failed with status: {}, body: {}",
                status, error_body
            )));
        }

        let json: Value = response.json().map_err(OidcError::NetworkError)?;

        if let Some(id_token) = json["id_token"].as_str() {
            match jwt_client::decode_jwt_without_verification(id_token) {
                Ok((header, payload)) => {
                    println!("Header: {:#?}", header);
                    println!("Payload: {:#?}", payload);
                }
                Err(e) => eprintln!("Failed to decode JWT: {}", e),
            };
        }

        Ok(TokenEndpointResponse {
            access_token: json["access_token"]
                .as_str()
                .ok_or_else(|| OidcError::MissingField("access_token".to_string()))?
                .to_string(),
            token_type: json["token_type"]
                .as_str()
                .ok_or_else(|| OidcError::MissingField("token_type".to_string()))?
                .to_string(),
            expires_in: json["expires_in"]
                .as_u64()
                .ok_or_else(|| OidcError::MissingField("expires_in".to_string()))?,
            refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
            scope: json["scope"].as_str().map(|s| s.to_string()),
            id_token: json["id_token"].as_str().map(|s| s.to_string()),
        })
    }

    pub fn get_user_info(&self, access_token: &str) -> Result<Value, OidcError> {
        let user_info_url = &self.well_knowns.user_info_url;
        let client = reqwest::blocking::Client::new();
        let response = client
            .get(user_info_url)
            .bearer_auth(access_token)
            .send()
            .map_err(OidcError::NetworkError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            println!(
                "User info request failed with status: {:?}, body: {}",
                status, error_body
            );
            return Err(OidcError::InvalidResponse(format!(
                "User info request failed with status: {}, body: {}",
                status, error_body
            )));
        }

        let json: Value = response.json().map_err(OidcError::NetworkError)?;
        Ok(json)
    }

    pub fn handle_error(&self, error: OidcError) -> Result<(), String> {
        eprintln!("An error occurred during the OIDC flow:\n{}", error);
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
        let mut client = Self {
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
            state,
        };

        client.well_knowns = client.fetch_well_knowns_from_issuer()?;

        Ok(client)
    }
}
