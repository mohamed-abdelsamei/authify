use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;

pub fn decode_jwt_without_verification(
    token: &str,
) -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".into());
    }

    let header = general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;

    let header_json: Value = serde_json::from_slice(&header)?;
    let payload_json: Value = serde_json::from_slice(&payload)?;

    Ok((header_json, payload_json))
}
