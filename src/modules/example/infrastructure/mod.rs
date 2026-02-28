use axum::{routing::get, Router};
use serde_json::json;
use sqlx::postgres::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub _auth_pool: PgPool,
}

pub mod controllers;
pub mod repositories;
pub mod services;


pub fn create_router(state: AppState) -> Router {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check));
    app.with_state(state)
}

async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"status": "ok", "service": "bidmart-admin-be"}))
}

async fn ready_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"ready": true}))
}
