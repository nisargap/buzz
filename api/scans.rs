use buzz::{fetch_saved_scan_by_id, fetch_user_saved_scans, templates, AppConfig};
use reqwest::Client;
use url::Url;
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    let config = AppConfig::from_env();
    let client = Client::new();

    if let Some(scan_id) = extract_query_param(&req, "id") {
        // 404 lets a page resuming an interrupted audit tell "not saved yet" from a real report
        let (status, html) = if let Some(report) = fetch_saved_scan_by_id(&client, &config, &scan_id).await {
            (StatusCode::OK, templates::render_audit_report(&report))
        } else {
            (
                StatusCode::NOT_FOUND,
                r#"<div class="pixel-box" style="padding:20px;color:var(--sev-critical);">Saved audit report not found.</div>"#.to_string(),
            )
        };

        return Ok(Response::builder()
            .status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::Text(html))?);
    }

    let user_id = req
        .headers()
        .get("x-supabase-user-id")
        .and_then(|v| v.to_str().ok());
    let gh_user = req
        .headers()
        .get("x-github-user")
        .and_then(|v| v.to_str().ok());

    let scans = fetch_user_saved_scans(&client, &config, user_id, gh_user).await;
    let html = templates::render_saved_scans_list(&scans);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn extract_query_param(req: &Request, key: &str) -> Option<String> {
    let raw_uri = req.uri().to_string();
    let full = if raw_uri.starts_with("http") {
        raw_uri
    } else {
        format!("http://localhost{}", raw_uri)
    };
    let parsed = Url::parse(&full).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}
