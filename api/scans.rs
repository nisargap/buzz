use buzz::{
    auth::authenticate, fetch_saved_scan_by_id, fetch_user_saved_scans, templates, AppConfig,
};
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
    let user = match authenticate(&client, &config, &req).await {
        Ok(user) => user,
        Err(message) => return error_response(StatusCode::UNAUTHORIZED, &message),
    };

    if let Some(scan_id) = extract_query_param(&req, "id") {
        // Missing and other users' scans are indistinguishable, including with a service key.
        let Some(report) = fetch_saved_scan_by_id(&client, &config, &scan_id, &user.id).await
        else {
            return error_response(StatusCode::NOT_FOUND, "Saved audit report not found.");
        };
        return html_response(StatusCode::OK, templates::render_audit_report(&report));
    }

    let scans = fetch_user_saved_scans(&client, &config, &user.id).await;
    html_response(StatusCode::OK, templates::render_saved_scans_list(&scans))
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
