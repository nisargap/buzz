use buzz::{run_buzz_codebase_chat_html, AppConfig};
use reqwest::Client;
use std::collections::HashMap;
use url::form_urlencoded;
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    let config = AppConfig::from_env();
    let client = Client::new();
    let user = match buzz::auth::authenticate(&client, &config, &req).await {
        Ok(user) => user,
        Err(message) => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-store")
                .body(Body::Text(buzz::templates::escape_html(&message)))?)
        }
    };

    let gh_token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (scan_id, repo, report_context, question) = parse_chat_body(req.body());
    let html = run_buzz_codebase_chat_html(
        &client,
        &config,
        &repo,
        if scan_id.is_empty() {
            None
        } else {
            Some(scan_id.as_str())
        },
        &report_context,
        &question,
        gh_token.as_deref(),
        Some(&user.id),
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn parse_chat_body(body: &Body) -> (String, String, String, String) {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => &[],
    };

    let mut map: HashMap<String, String> = HashMap::new();
    for (k, v) in form_urlencoded::parse(raw_bytes) {
        map.insert(k.into_owned(), v.into_owned());
    }

    let scan_id = map.remove("scan_id").unwrap_or_default();
    let repo = map
        .remove("repo")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "nisargap/buzz".to_string());
    let report_context = map.remove("report_context").unwrap_or_default();
    let question = map.remove("question").unwrap_or_default();

    (scan_id, repo, report_context, question)
}
