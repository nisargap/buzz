use buzz::{
    fetch_repo_snapshot, fetch_saved_scan_by_id, generate_codebase_diagram, save_diagram_to_scan,
    templates, AppConfig,
};
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

    let gh_token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (scan_id, repo_full_name, return_full_report) = parse_diagram_body(req.body());

    // 1. Fetch repository files into the 1M context window
    let snapshot =
        fetch_repo_snapshot(&client, &config, &repo_full_name, gh_token.as_deref()).await;

    // 2. Synthesize the Component Flow Diagram via Gemini 4 Argon
    let diagram = generate_codebase_diagram(&client, &config, &snapshot).await;

    // 3. Persist the generated diagram onto the existing scan record in Supabase
    if !scan_id.is_empty() {
        save_diagram_to_scan(&client, &config, &scan_id, &diagram).await;
    }

    // 4. Return either the full updated report HTML (when triggered from Saved Audits list)
    //    or the standalone diagram section HTML
    let html = if return_full_report && !scan_id.is_empty() {
        if let Some(mut saved_report) = fetch_saved_scan_by_id(&client, &config, &scan_id).await {
            saved_report.diagram = Some(diagram);
            templates::render_audit_report(&saved_report)
        } else {
            templates::render_component_diagram(&snapshot.full_name, &diagram)
        }
    } else {
        templates::render_component_diagram(&snapshot.full_name, &diagram)
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn parse_diagram_body(body: &Body) -> (String, String, bool) {
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
    let full_report = map
        .remove("full_report")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    (scan_id, repo, full_report)
}
