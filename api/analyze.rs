use buzz::{
    fetch_cves, fetch_repo_snapshot, generate_codebase_diagram, is_uuid, persist_scan_report,
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
    if req.method().as_str() != "POST" {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("allow", "POST")
            .body(Body::Empty)?);
    }
    let config = AppConfig::from_env();
    let started = std::time::Instant::now();
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .build()?;
    let user = match buzz::auth::authenticate(&client, &config, &req).await {
        Ok(user) => user,
        Err(message) => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-store")
                .body(Body::Text(format!(
                    "<p role=\"alert\">{}</p>",
                    templates::escape_html(&message)
                )))?)
        }
    };

    let gh_token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if gh_token.is_none() {
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

    let (repo_opt, include_diagram, job_id) = extract_params_from_body(req.body());
    let repo_target = repo_opt.unwrap_or_else(|| "nisargap/buzz".to_string());

    // 1. Fetch repository files from GitHub
    let snapshot = match tokio::time::timeout(
        std::time::Duration::from_secs(18),
        fetch_repo_snapshot(&client, &config, &repo_target, gh_token.as_deref()),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::GATEWAY_TIMEOUT)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::Text(
                "<p role=\"alert\">Repository loading timed out. Please retry the analysis.</p>"
                    .into(),
            ))?),
    };

    // All analysis uses the same pinned source. Reserve time for persistence/rendering.
    let cves = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        fetch_cves(&client, &config, None),
    )
    .await
    .unwrap_or_else(|_| buzz::builtin_seed_cves());
    let budget = std::time::Duration::from_secs(48).saturating_sub(started.elapsed());
    let security = async {
        match tokio::time::timeout(
            budget,
            run_gemini_argon_audit(&client, &config, &snapshot, &cves),
        )
        .await
        {
            Ok(report) => report,
            Err(_) => {
                let mut offline = config.clone();
                offline.gemini_api_key = None;
                run_gemini_argon_audit(&client, &offline, &snapshot, &cves).await
            }
        }
    };
    let refactoring = async {
        tokio::time::timeout(
            budget,
            buzz::refactoring::analyze_refactoring(&client, &config, &snapshot),
        )
        .await
        .unwrap_or_else(|_| {
            buzz::refactoring::RefactoringResult::unavailable(
                "Refactoring analysis timed out. Security results are still available.",
            )
        })
    };
    let diagram = async {
        if include_diagram {
            tokio::time::timeout(
                budget,
                generate_codebase_diagram(&client, &config, &snapshot),
            )
            .await
            .ok()
        } else {
            None
        }
    };
    let (mut report, refactoring, diagram) = tokio::join!(security, refactoring, diagram);
    report.refactoring = refactoring;
    report.diagram = diagram;
    report.source_verified =
        buzz::refactoring::is_commit_sha(&snapshot.commit_sha) && !snapshot.files.is_empty();

    // 4. Persist audit report to Supabase scans & scan_findings tables for the logged-in user
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        persist_scan_report(
            &client,
            &config,
            &mut report,
            Some(&user.id),
            Some(&user.github_login),
            job_id.as_deref(),
        ),
    )
    .await;

    // 5. Render visually appealing pixel-art HTML report for HTMX swap
    let html = templates::render_audit_report(&report);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::Text(html))?)
}

fn extract_params_from_body(body: &Body) -> (Option<String>, bool, Option<String>) {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => return (None, false, None),
    };

    let mut repo_val = None;
    let mut include_diagram = false;
    let mut job_id = None;

    for (k, v) in form_urlencoded::parse(raw_bytes) {
        if k == "repo" && !v.trim().is_empty() {
            repo_val = Some(v.trim().to_string());
        } else if k == "include_diagram" {
            let low = v.trim().to_ascii_lowercase();
            include_diagram = low == "true" || low == "on" || low == "1";
        } else if k == "job_id" && is_uuid(v.trim()) {
            job_id = Some(v.trim().to_string());
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

    (repo_val, include_diagram, job_id)
}
