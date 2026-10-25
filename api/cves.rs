use buzz::{fetch_cves, templates, AppConfig};
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

    let ecosystem = extract_query_param(&req, "ecosystem");
    let cves = fetch_cves(&client, &config, ecosystem.as_deref()).await;
    let html = templates::render_cve_table(&cves);

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
