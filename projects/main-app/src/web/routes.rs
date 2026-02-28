use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::services::ServeDir;

use crate::app_state::AppState;

use super::handlers;

pub fn build_router(state: Arc<AppState>) -> Router {
    let protected_routes = Router::new()
        .route("/status", get(handlers::status))
        .route("/cameras", get(handlers::cameras))
        .route("/camera/select", post(handlers::camera_select))
        .route("/start", post(handlers::start))
        .route("/stop", post(handlers::stop))
        .route("/stream", get(handlers::stream))
        .route("/snapshot", get(handlers::snapshot))
        .route("/panic", post(handlers::panic))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            super::middleware::require_auth,
        ));

    Router::new()
        .route("/", get(handlers::root))
        .route("/health", get(handlers::health))
        .route("/login", post(handlers::login))
        .merge(protected_routes)
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
}
