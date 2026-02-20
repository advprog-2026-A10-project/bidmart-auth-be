pub mod auth;
pub mod health;

use axum::{
    Router,
    http::{
        HeaderValue, Method,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    routing::{get, post},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config.cors_origin);

    Router::new()
        .route("/health", get(health::health))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/logout", post(auth::logout))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

fn build_cors_layer(origin: &str) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    if origin == "*" {
        return base.allow_origin(tower_http::cors::Any);
    }

    match HeaderValue::from_str(origin) {
        Ok(value) => base.allow_origin([value]),
        Err(_) => {
            tracing::warn!(origin, "invalid CORS_ORIGIN value, using wildcard");
            base.allow_origin(tower_http::cors::Any)
        }
    }
}
