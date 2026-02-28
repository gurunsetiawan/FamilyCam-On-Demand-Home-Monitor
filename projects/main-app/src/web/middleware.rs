use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::COOKIE},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::app_state::AppState;

fn cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let mut parts = pair.trim().splitn(2, '=');
        let name = parts.next()?;
        let value = parts.next()?;
        if name == cookie_name {
            Some(value.to_owned())
        } else {
            None
        }
    })
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response<Body>, Response<Body>> {
    let authenticated = cookie_value(request.headers(), state.session_cookie_name)
        .map(|v| v == state.session_token)
        .unwrap_or(false);

    if authenticated {
        return Ok(next.run(request).await);
    }

    Err((StatusCode::UNAUTHORIZED, "login required").into_response())
}
