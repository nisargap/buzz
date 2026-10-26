use crate::{is_uuid, AppConfig};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use vercel_runtime::Request;

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub id: String,
    pub github_id: String,
    pub github_login: String,
}

#[derive(Deserialize)]
struct SupabaseUser {
    id: String,
    #[serde(default)]
    identities: Vec<SupabaseIdentity>,
}

#[derive(Deserialize)]
struct SupabaseIdentity {
    provider: String,
    #[serde(default)]
    id: Value,
    #[serde(default)]
    identity_data: Value,
}

/// Verifies a Supabase session, not the separately supplied GitHub provider token.
/// Callers performing GitHub writes must also match `/user` to `github_id`.
pub async fn authenticate(
    client: &Client,
    config: &AppConfig,
    request: &Request,
) -> Result<AuthenticatedUser, String> {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Sign in with GitHub to continue.".to_string())?;
    let mut parts = authorization.split_whitespace();
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 16_384
        || parts.next().is_some()
    {
        return Err("A valid Supabase bearer token is required.".to_string());
    }

    let (Some(base_url), Some(anon_key)) = (&config.supabase_url, &config.supabase_anon_key) else {
        return Err("Authentication is not configured.".to_string());
    };
    let mut response = client
        .get(format!("{}/auth/v1/user", base_url.trim_end_matches('/')))
        .header("apikey", anon_key)
        .bearer_auth(token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| "Unable to verify your session. Please sign in again.".to_string())?;
    if !response.status().is_success() {
        return Err("Your session is invalid or expired. Please sign in again.".to_string());
    }

    const MAX_AUTH_RESPONSE_BYTES: usize = 128 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Unable to read the verified session.".to_string())?
    {
        if body.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
            return Err("The authentication response was too large.".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let user: SupabaseUser = serde_json::from_slice(&body)
        .map_err(|_| "Unable to read the verified session.".to_string())?;
    if !is_uuid(&user.id) {
        return Err("The verified session has no valid user ID.".to_string());
    }

    // Only the server-verified linked identity is authoritative; headers and
    // editable user_metadata must never supply an owner or GitHub identity.
    let mut identities = user
        .identities
        .iter()
        .filter(|identity| identity.provider == "github");
    let identity = identities
        .next()
        .ok_or_else(|| "Connect a GitHub identity to continue.".to_string())?;
    if identities.next().is_some() {
        return Err("The session has an ambiguous GitHub identity.".to_string());
    }
    let github_id = [
        identity.identity_data.get("sub"),
        identity.identity_data.get("provider_id"),
        Some(&identity.id),
    ]
    .into_iter()
    .flatten()
    .find_map(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
    })
    .ok_or_else(|| "The linked GitHub identity has no stable user ID.".to_string())?;
    let github_login = ["user_name", "preferred_username", "login"]
        .into_iter()
        .filter_map(|key| identity.identity_data.get(key).and_then(Value::as_str))
        .find(|login| {
            !login.is_empty()
                && login.len() <= 39
                && login
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| "The linked GitHub identity has no valid login.".to_string())?;

    Ok(AuthenticatedUser {
        id: user.id.to_ascii_lowercase(),
        github_id,
        github_login: github_login.to_string(),
    })
}
