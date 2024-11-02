use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str;

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
/// Represents an OpenID Connect (OIDC) agent for handling authentication and token management.
///
/// This struct encapsulates the necessary information and methods to interact with an OIDC provider,
/// including client credentials, redirect URL, requested scope, and well-known OIDC configuration endpoints.
/// It provides methods for authorization URL building, token retrieval, and well-known configuration management.
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
    /// Returns a reference to the well-known OIDC configuration.
    ///
    /// # Returns
    ///
    /// A reference to the `WellKnowns` struct containing OIDC endpoints.
    /// Returns a reference to the well-known OIDC configuration.
    ///
    /// # Returns
    ///
    /// A reference to the `WellKnowns` struct containing OIDC endpoints.
    pub fn get_well_knowns(&self) -> &WellKnowns {
        &self.well_knowns
    }

    /// Fetches the OIDC well-known configuration from the issuer URL.
    ///
    /// This method sends an HTTP GET request to the standard OIDC discovery endpoint
    /// and parses the JSON response into a WellKnowns struct.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the `WellKnowns` struct or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The HTTP request fails
    /// - The response cannot be parsed as valid JSON
    /// - Any required fields are missing from the well-known configuration
    fn fetch_well_knowns_from_issuer(&self) -> Result<WellKnowns, Box<dyn std::error::Error>> {
        let well_known_url = format!("{}/.well-known/openid-configuration", self.issuer);
        self.fetch_well_knowns_from_custom_url(&well_known_url)
    }

    /// Fetches the OIDC well-known configuration from a custom URL.
    ///
    /// This method sends an HTTP GET request to the provided URL
    /// and parses the JSON response into a WellKnowns struct.
    ///
    /// # Arguments
    ///
    /// * `url` - A string slice that holds the custom URL to fetch the well-known configuration from.
    ///
    /// # Errors
    ///
    /// This function will return an error if the HTTP request fails or if the
    /// response cannot be parsed as valid JSON.
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

    /// Builds the authorization URL for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `String` containing the complete authorization URL.
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

    /// Returns the token URL from the well-known OIDC configuration.
    ///
    /// # Returns
    ///
    /// A `String` containing the token URL.
    /// Builds the token URL for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `String` containing the token URL.
    pub fn build_token_url(&self) -> String {
        self.well_knowns.token_url.clone()
    }

    /// Exchanges an authorization code for an access token.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code received from the OIDC provider.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the access token as a `String` or an error.
    /// Retrieves an access token using the authorization code.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code received from the OIDC provider.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the access token as a `String` or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The HTTP request to the token endpoint fails.
    /// - The response status is not successful.
    /// - The response cannot be parsed as valid JSON.
    /// - The access token is not found in the response.
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

    /// Handles errors that may occur during the OIDC flow
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred
    ///
    /// # Returns
    ///
    /// A `Result` with the error message as a `String`
    pub fn handle_error(&self, error: Box<dyn std::error::Error>) -> Result<(), String> {
        eprintln!("An error occurred during the OIDC flow: {}", error);
        Err(error.to_string())
    }

    /// Creates a new OidcAgent instance.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer URL for the OIDC provider.
    /// * `client_id` - The client ID for this OIDC client.
    /// * `client_secret` - The client secret for this OIDC client.
    /// * `redirect_url` - The redirect URL for the OIDC flow.
    /// * `scope` - The scope requested for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the new OidcAgent instance or an error.
    /// Creates a new OidcAgent instance.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer URL for the OIDC provider.
    /// * `client_id` - The client ID for this OIDC client.
    /// * `client_secret` - The client secret for this OIDC client.
    /// * `redirect_url` - The redirect URL for the OIDC flow.
    /// * `scope` - The scope requested for the OIDC flow.
    /// * `state` - An optional state parameter for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the new OidcAgent instance or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The well-known configuration cannot be fetched from the issuer.
    /// - Any of the required fields in the well-known configuration are missing.
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
