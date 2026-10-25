use buzz::{refactor, AppConfig};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use url::Url;
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

fn reply(status: u16, body: Value) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::Text(body.to_string()))?)
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    let token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token.trim().is_empty() || token.len() > 4096 {
        return reply(
            401,
            json!({"error":"Sign in with GitHub using the existing Connect GitHub button. A username alone cannot authorize refactoring."}),
        );
    }
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(40))
        .build()?;
    let result = if req.method().as_str() == "GET" {
        let uri = format!(
            "https://buzz.invalid{}",
            req.uri()
                .path_and_query()
                .map(|v| v.as_str())
                .unwrap_or("/")
        );
        let parsed = Url::parse(&uri)?;
        let repo = parsed
            .query_pairs()
            .find(|(key, _)| key == "repo")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        tokio::time::timeout(
            Duration::from_secs(50),
            refactor::discover(&client, token, &repo),
        )
        .await
    } else if req.method().as_str() == "POST" {
        if !req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("application/json")
        {
            return reply(415, json!({"error":"Send an application/json request."}));
        }
        let bytes: &[u8] = match req.body() {
            Body::Text(value) => value.as_bytes(),
            Body::Binary(value) => value,
            Body::Empty => &[],
        };
        if bytes.len() > 300_000 {
            return reply(413, json!({"error":"Request exceeds the 300 KB limit."}));
        }
        let action = match serde_json::from_slice::<refactor::Action>(bytes) {
            Ok(action) => action,
            Err(_) => return reply(400, json!({"error":"Invalid refactoring request."})),
        };
        let config = AppConfig::from_env();
        tokio::time::timeout(
            Duration::from_secs(50),
            refactor::execute(&client, &config, token, action),
        )
        .await
    } else {
        return reply(405, json!({"error":"Only GET and POST are supported."}));
    };
    match result {
        Ok(Ok(body)) => reply(200, body),
        Ok(Err(error)) => reply(error.status, json!({"error": error.message})),
        Err(_) => reply(
            504,
            json!({"error":"Request timed out. If you were opening a draft PR, check GitHub before retrying; a branch or PR may already have been created."}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refactor_requires_connected_user_not_server_fallback() {
        let mut req = Request::new(Body::Empty);
        *req.uri_mut() = "/api/refactor?repo=owner/repo".parse().unwrap();
        let response = handler(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn refactor_rejects_unsupported_request_without_provider_calls() {
        let mut req = Request::new(Body::Empty);
        *req.method_mut() = "DELETE".parse().unwrap();
        req.headers_mut()
            .insert("x-github-token", "test-token".parse().unwrap());
        let response = handler(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let mut req = Request::new(Body::Text("{}".into()));
        *req.method_mut() = "POST".parse().unwrap();
        req.headers_mut()
            .insert("x-github-token", "test-token".parse().unwrap());
        let response = handler(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
