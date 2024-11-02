use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WellKnowns {
    auth_url: String,
    token_url: String,
    user_info_url: String,
    jwks_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents an OpenID Connect (OIDC) agent for handling authentication and token management.
pub struct OidcAgent {
    /// The issuer URL for the OIDC provider.
    issuer: String,
    /// The client ID for this OIDC client.
    client_id: String,
    /// The client secret for this OIDC client.
    client_secret: String,
    /// The redirect URL for the OIDC flow.
    redirect_url: String,
    /// The scopes requested for the OIDC flow.
    scopes: Vec<String>,
    /// The well-known OIDC configuration endpoints.
    well_knowns: WellKnowns,
}
impl OidcAgent {
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
    /// # Errors
    ///
    /// This function will return an error if the HTTP request fails or if the
    /// response cannot be parsed as valid JSON.
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
        let json: Value = response.json()?;

        Ok(WellKnowns {
            auth_url: json["authorization_endpoint"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            token_url: json["token_endpoint"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            user_info_url: json["userinfo_endpoint"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            jwks_url: json["jwks_uri"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Builds the authorization URL for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `String` containing the complete authorization URL.
    pub fn build_authorization_url(&self) -> String {
        let scopes = self.scopes.join(" ");
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}",
            self.well_knowns.auth_url, self.client_id, self.redirect_url, scopes
        )
    }

    /// Returns the token URL from the well-known OIDC configuration.
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
    pub fn get_token(&self, code: &str) -> Result<String, Box<dyn std::error::Error>> {
        let token_url = self.build_token_url();

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_url),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];

        let client = reqwest::blocking::Client::new();
        let response = client.post(token_url).form(&params).send()?;

        let json: Value = response.json()?;
        json["access_token"]
            .as_str()
            .ok_or_else(|| "Access token not found in response".into())
            .map(String::from)
    }

    /// Creates a new OidcAgent instance.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer URL for the OIDC provider.
    /// * `client_id` - The client ID for this OIDC client.
    /// * `client_secret` - The client secret for this OIDC client.
    /// * `redirect_url` - The redirect URL for the OIDC flow.
    /// * `scopes` - The scopes requested for the OIDC flow.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the new OidcAgent instance or an error.
    pub fn new(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
        scopes: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut agent = Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_url: redirect_url.to_string(),
            scopes,
            well_knowns: WellKnowns {
                auth_url: String::new(),
                token_url: String::new(),
                user_info_url: String::new(),
                jwks_url: String::new(),
            },
        };

        agent.well_knowns = agent.fetch_well_knowns_from_issuer()?;

        Ok(agent)
    }
}
