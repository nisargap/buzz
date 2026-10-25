use buzz::{create_remediation_pull_request, templates, AppConfig, PatchRequest};
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
        .map(|s| s.to_string());

    let patch_req = parse_patch_request(req.body());
    let outcome =
        create_remediation_pull_request(&client, &config, &patch_req, gh_token.as_deref()).await;
    let html = templates::render_pr_outcome(&outcome);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}

fn parse_patch_request(body: &Body) -> PatchRequest {
    let raw_bytes: &[u8] = match body {
        Body::Text(s) => s.as_bytes(),
        Body::Binary(b) => b.as_slice(),
        Body::Empty => &[],
    };

    let mut map: HashMap<String, String> = HashMap::new();
    for (k, v) in form_urlencoded::parse(raw_bytes) {
        map.insert(k.into_owned(), v.into_owned());
    }

    PatchRequest {
        repo: map
            .remove("repo")
            .unwrap_or_else(|| "nisargap/buzz".to_string()),
        branch: map.remove("branch").unwrap_or_else(|| "main".to_string()),
        cve_id: map
            .remove("cve_id")
            .unwrap_or_else(|| "CVE-PATCH".to_string()),
        title: map
            .remove("title")
            .unwrap_or_else(|| "Security Remediation".to_string()),
        file_path: map
            .remove("file_path")
            .unwrap_or_else(|| "README.md".to_string()),
        line_reference: map
            .remove("line_reference")
            .unwrap_or_else(|| "L1".to_string()),
        remediation_patch: map.remove("remediation_patch").unwrap_or_default(),
    }
}
