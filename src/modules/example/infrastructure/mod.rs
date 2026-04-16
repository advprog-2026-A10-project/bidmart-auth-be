use std::sync::Arc;

use axum::{routing::get, routing::post, Router};
use serde_json::json;

use crate::modules::auth::application::use_cases::auth_mfa_use_case::AuthMfaUseCase;
use crate::modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use crate::modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use crate::modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use crate::modules::auth::domain::traits::{Clock, JwtService, SessionRepository};

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub verify_email_use_case: Arc<VerifyEmailUseCase>,
    pub resend_verification_use_case: Arc<ResendVerificationUseCase>,
    pub auth_mfa_use_case: Arc<AuthMfaUseCase>,
    pub jwt_service: Arc<dyn JwtService>,
    pub session_repository: Arc<dyn SessionRepository>,
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        register_use_case: Arc<RegisterUserUseCase>,
        verify_email_use_case: Arc<VerifyEmailUseCase>,
        resend_verification_use_case: Arc<ResendVerificationUseCase>,
        auth_mfa_use_case: Arc<AuthMfaUseCase>,
        jwt_service: Arc<dyn JwtService>,
        session_repository: Arc<dyn SessionRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            register_use_case,
            verify_email_use_case,
            resend_verification_use_case,
            auth_mfa_use_case,
            jwt_service,
            session_repository,
            clock,
        }
    }
}

pub mod auth_extractor;
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
        )
        .route("/auth/login", post(controllers::login))
        .route("/auth/mfa/send-email", post(controllers::send_email_mfa))
        .route(
            "/auth/mfa/verify-email",
            post(controllers::verify_email_mfa),
        )
        .route("/auth/mfa/verify-totp", post(controllers::verify_totp_mfa))
        .route("/settings/security/mfa", get(controllers::get_mfa_settings))
        .route(
            "/settings/security/mfa/totp/setup",
            post(controllers::setup_totp),
        )
        .route(
            "/settings/security/mfa/totp/verify",
            post(controllers::verify_totp_setup),
        )
        .route(
            "/settings/security/mfa/email/setup",
            post(controllers::setup_email_mfa),
        )
        .route(
            "/settings/security/mfa/email/verify",
            post(controllers::verify_email_mfa_setup),
        )
        .route(
            "/settings/security/mfa/disable",
            post(controllers::disable_mfa),
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
