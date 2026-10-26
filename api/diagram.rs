use buzz::{
    auth::authenticate, fetch_repo_snapshot, fetch_saved_scan_by_id, generate_codebase_diagram,
    save_diagram_to_scan, templates, AppConfig,
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
    let user = match authenticate(&client, &config, &req).await {
        Ok(user) => user,
        Err(message) => return error_response(StatusCode::UNAUTHORIZED, &message),
    };
    let gh_token = req
        .headers()
        .get("x-github-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let (scan_id, requested_repo, return_full_report) = parse_diagram_body(req.body());

    // Authorize before accessing source or invoking Gemini. A supplied scan's
    // stored repository is authoritative, not a caller-controlled form field.
    let mut saved_report = if scan_id.is_empty() {
        None
    } else {
        let Some(report) = fetch_saved_scan_by_id(&client, &config, &scan_id, &user.id).await
        else {
            return error_response(StatusCode::NOT_FOUND, "Saved audit report not found.");
        };
        Some(report)
    };
    let repo_full_name = saved_report
        .as_ref()
        .map(|report| report.repo_full_name.as_str())
        .unwrap_or(&requested_repo);
    if repo_full_name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "A repository is required.");
    }
    let snapshot = fetch_repo_snapshot(&client, &config, repo_full_name, gh_token).await;
    if snapshot.files.is_empty() || snapshot.commit_sha.is_empty() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unable to load a pinned repository snapshot. Check your GitHub access and try again.",
        );
    }
    let diagram = generate_codebase_diagram(&client, &config, &snapshot).await;

    // Repeat the owner predicate on the write itself; a service key bypasses RLS.
    if !scan_id.is_empty()
        && !save_diagram_to_scan(&client, &config, &scan_id, &user.id, &diagram).await
    {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "Unable to save the generated diagram.",
        );
    }
    let html = if return_full_report {
        if let Some(report) = saved_report.as_mut() {
            report.diagram = Some(diagram);
            templates::render_audit_report(report)
        } else {
            templates::render_component_diagram(&snapshot.full_name, &diagram)
        }
    } else {
        templates::render_component_diagram(&snapshot.full_name, &diagram)
    };
    html_response(StatusCode::OK, html)
}

fn error_response(status: StatusCode, message: &str) -> Result<Response<Body>, Error> {
    html_response(
        status,
        format!(
            r#"<div class="pixel-box" role="alert" style="padding:20px;color:var(--sev-critical);">{}</div>"#,
            templates::escape_html(message)
        ),
    )
}

fn html_response(status: StatusCode, html: String) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::Text(html))?)
}

fn parse_diagram_body(body: &Body) -> (String, String, bool) {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => &[],
    };
    let mut map: HashMap<String, String> = form_urlencoded::parse(raw_bytes).into_owned().collect();
    let scan_id = map.remove("scan_id").unwrap_or_default().trim().to_string();
    let repo = map.remove("repo").unwrap_or_default().trim().to_string();
    let full_report = map
        .remove("full_report")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    (scan_id, repo, full_report)
}
