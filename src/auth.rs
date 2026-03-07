use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose, Engine as _};

use crate::config::Config;

pub async fn basic_auth_middleware(
    State(config): State<Config>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            let encoded = &auth[6..];
            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let username = parts[0];
                        let password = parts[1];

                        if username == config.auth.username && password == config.auth.password {
                            return Ok(next.run(request).await);
                        }
                    }
                }
            }
        }
    }

    // Authentication failed - return 401 with WWW-Authenticate header
    Ok((
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"WireGuard Manager\"")],
        "Authentication required",
    )
        .into_response())
}
