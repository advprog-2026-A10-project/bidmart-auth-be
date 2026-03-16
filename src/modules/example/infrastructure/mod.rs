use std::sync::Arc;

use axum::{routing::get, routing::post, Router};
use serde_json::json;

use crate::modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use crate::modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use crate::modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub verify_email_use_case: Arc<VerifyEmailUseCase>,
    pub resend_verification_use_case: Arc<ResendVerificationUseCase>,
}

impl AppState {
    pub fn new(
        register_use_case: Arc<RegisterUserUseCase>,
        verify_email_use_case: Arc<VerifyEmailUseCase>,
        resend_verification_use_case: Arc<ResendVerificationUseCase>,
    ) -> Self {
        Self {
            register_use_case,
            verify_email_use_case,
            resend_verification_use_case,
        }
    }
}

pub mod controllers;
pub mod repositories;
pub mod services;

pub fn create_router(state: AppState) -> Router {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/auth/register", post(controllers::register))
        .route("/auth/verify-email", post(controllers::verify_email))
        .route(
            "/auth/resend-verification",
            post(controllers::resend_verification),
        );
    app.with_state(state)
}

async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"status": "ok", "service": "bidmart-auth-be"}))
}

async fn ready_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"ready": true}))
}

#[cfg(test)]
mod contract_tests;
