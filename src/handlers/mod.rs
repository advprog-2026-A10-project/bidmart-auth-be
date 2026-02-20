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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sqlx::postgres::PgPoolOptions;

    use crate::{config::Config, state::AppState};

    use super::{build_cors_layer, build_router};

    fn test_state_with_origin(origin: &str) -> AppState {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
            .expect("pool should be created");

        let config = Arc::new(Config {
            app_host: "127.0.0.1".to_owned(),
            app_port: 8080,
            database_url: "postgres://postgres:postgres@localhost:5432/postgres".to_owned(),
            database_max_connections: 1,
            jwt_secret: "01234567890123456789012345678901".to_owned(),
            jwt_expiry_minutes: 30,
            cors_origin: origin.to_owned(),
        });

        AppState { pool, config }
    }

    #[tokio::test]
    async fn router_builds_with_wildcard_origin() {
        let state = test_state_with_origin("*");
        let _router = build_router(state);
    }

    #[tokio::test]
    async fn router_builds_with_specific_origin() {
        let state = test_state_with_origin("http://localhost:5173");
        let _router = build_router(state);
    }

    #[test]
    fn cors_layer_handles_invalid_origin() {
        let _layer = build_cors_layer("invalid header value \r\n");
    }
}
