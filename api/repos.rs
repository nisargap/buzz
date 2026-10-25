use buzz::{fetch_user_repos, templates, AppConfig};
use reqwest::Client;
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
        .and_then(|v| v.to_str().ok());
    let gh_user = req
        .headers()
        .get("x-github-user")
        .and_then(|v| v.to_str().ok());

    let repos = fetch_user_repos(&client, &config, gh_token, gh_user).await;
    let html = templates::render_repo_selector(&repos);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::Text(html))?)
}
