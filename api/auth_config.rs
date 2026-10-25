use buzz::AppConfig;
use serde_json::json;
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

pub async fn handler(_req: Request) -> Result<Response<Body>, Error> {
    let config = AppConfig::from_env();
    let payload = json!({
        "supabase_url": config.supabase_url.unwrap_or_default(),
        "supabase_anon_key": config.supabase_anon_key.unwrap_or_default(),
        "gemini_model": config.gemini_model,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::Text(payload.to_string()))?)
}
