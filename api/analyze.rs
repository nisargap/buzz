use buzz::{
    fetch_cves, fetch_repo_snapshot, persist_scan_report, run_gemini_argon_audit, templates,
    AppConfig,
};
use reqwest::Client;
use url::form_urlencoded;
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    let config = AppConfig::from_env();
    let client = Client::new();

    let gh_token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let repo_target = extract_repo_from_body(req.body())
        .unwrap_or_else(|| "acme-labs/payment-gateway-rs".to_string());

    // 1. Fetch repository files from GitHub (or built-in connected repo snapshot)
    let snapshot = fetch_repo_snapshot(&client, &config, &repo_target, gh_token.as_deref()).await;

    // 2. Load CVE datasource from Supabase
    let cves = fetch_cves(&client, &config, None).await;

    // 3. Run Gemini 4 Argon CVE correlation & code analysis
    let report = run_gemini_argon_audit(&client, &config, &snapshot, &cves).await;

    // 4. Persist audit report to Supabase scans & scan_findings tables
    persist_scan_report(&client, &config, &report).await;

    // 5. Render visually appealing pixel-art HTML report for HTMX swap
    let html = templates::render_audit_report(&report);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn extract_repo_from_body(body: &Body) -> Option<String> {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => return None,
    };

    // Try application/x-www-form-urlencoded (default for HTMX form POST)
    for (k, v) in form_urlencoded::parse(raw_bytes) {
        if k == "repo" && !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }

    // Try JSON payload fallback: {"repo": "owner/repo"}
    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(raw_bytes) {
        if let Some(repo) = json_val.get("repo").and_then(|r| r.as_str()) {
            if !repo.trim().is_empty() {
                return Some(repo.trim().to_string());
            }
        }
    }

    None
}
