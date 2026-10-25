use buzz::{
    fetch_cves, fetch_repo_snapshot, generate_codebase_diagram, persist_scan_report,
    run_gemini_argon_audit, templates, AppConfig,
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
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let user_id = req
        .headers()
        .get("x-supabase-user-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let gh_user = req
        .headers()
        .get("x-github-user")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Enforce authentication: do not allow scanning unless logged in with GitHub via Supabase Auth
    if gh_token.is_none() && user_id.is_none() && gh_user.is_none() {
        let unauthorized_html = r#"<div class="pixel-box-gold" style="padding:28px;text-align:center;">
            <div style="font-family:var(--font-display);color:var(--buzz-yellow);font-size:0.95rem;margin-bottom:12px;">
                🔒 GITHUB SIGN-IN REQUIRED TO ANALYZE REPOSITORIES
            </div>
            <p style="font-family:var(--font-code);color:var(--text-muted);font-size:0.88rem;margin-bottom:18px;">
                Please sign in with your GitHub account via Supabase Auth to run 1M-context repository scans and create Pull Request patches.
            </p>
            <button type="button" class="pixel-btn pixel-btn-primary" onclick="window.buzzConnectGitHub()">
                ⚡ SIGN IN WITH GITHUB
            </button>
        </div>"#;

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::Text(unauthorized_html.to_string()))?);
    }

    let (repo_opt, include_diagram) = extract_params_from_body(req.body());
    let repo_target = repo_opt.unwrap_or_else(|| "nisargap/buzz".to_string());

    // 1. Fetch repository files from GitHub
    let snapshot = fetch_repo_snapshot(&client, &config, &repo_target, gh_token.as_deref()).await;

    // 2. Load CVE datasource from Supabase
    let cves = fetch_cves(&client, &config, None).await;

    // 3. Run Gemini 4 Argon CVE correlation (+ optional Component Flow Diagram generation)
    let mut report = if include_diagram {
        let (mut rep, diag) = tokio::join!(
            run_gemini_argon_audit(&client, &config, &snapshot, &cves),
            generate_codebase_diagram(&client, &config, &snapshot)
        );
        rep.diagram = Some(diag);
        rep
    } else {
        run_gemini_argon_audit(&client, &config, &snapshot, &cves).await
    };

    // 4. Persist audit report to Supabase scans & scan_findings tables for the logged-in user
    persist_scan_report(
        &client,
        &config,
        &mut report,
        user_id.as_deref(),
        gh_user.as_deref(),
    )
    .await;

    // 5. Render visually appealing pixel-art HTML report for HTMX swap
    let html = templates::render_audit_report(&report);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn extract_params_from_body(body: &Body) -> (Option<String>, bool) {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => return (None, false),
    };

    let mut repo_val = None;
    let mut include_diagram = false;

    for (k, v) in form_urlencoded::parse(raw_bytes) {
        if k == "repo" && !v.trim().is_empty() {
            repo_val = Some(v.trim().to_string());
        } else if k == "include_diagram" {
            let low = v.trim().to_ascii_lowercase();
            include_diagram = low == "true" || low == "on" || low == "1";
        }
    }

    if repo_val.is_none() {
        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(raw_bytes) {
            if let Some(repo) = json_val.get("repo").and_then(|r| r.as_str()) {
                if !repo.trim().is_empty() {
                    repo_val = Some(repo.trim().to_string());
                }
            }
            if let Some(inc) = json_val.get("include_diagram").and_then(|b| b.as_bool()) {
                include_diagram = inc;
            }
        }
    }

    (repo_val, include_diagram)
}
