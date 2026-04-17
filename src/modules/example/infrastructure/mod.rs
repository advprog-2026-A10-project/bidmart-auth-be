use std::sync::Arc;

use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tower_http::cors::CorsLayer;

use crate::modules::auth::application::use_cases::auth_mfa_use_case::AuthMfaUseCase;
use crate::modules::auth::application::use_cases::password_reset_use_case::{
    ForgotPasswordUseCase, ResetPasswordUseCase,
};
use crate::modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use crate::modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use crate::modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use crate::modules::auth::domain::traits::{Clock, JwtService, SessionRepository};

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub verify_email_use_case: Arc<VerifyEmailUseCase>,
    pub resend_verification_use_case: Arc<ResendVerificationUseCase>,
    pub forgot_password_use_case: Arc<ForgotPasswordUseCase>,
    pub reset_password_use_case: Arc<ResetPasswordUseCase>,
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
        forgot_password_use_case: Arc<ForgotPasswordUseCase>,
        reset_password_use_case: Arc<ResetPasswordUseCase>,
        auth_mfa_use_case: Arc<AuthMfaUseCase>,
        jwt_service: Arc<dyn JwtService>,
        session_repository: Arc<dyn SessionRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            register_use_case,
            verify_email_use_case,
            resend_verification_use_case,
            forgot_password_use_case,
            reset_password_use_case,
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

#[cfg(test)]
pub fn create_router(state: AppState) -> Router {
    create_router_with_cors_origins(
        state,
        &[
            "http://localhost:5173".to_string(),
            "http://127.0.0.1:5173".to_string(),
        ],
    )
}

pub fn create_router_with_cors_origins(state: AppState, allowed_origins: &[String]) -> Router {
    let allowed_origins = allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::try_from(origin.as_str())
                .expect("CORS origins are validated during configuration loading")
        })
        .collect::<Vec<_>>();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::ACCEPT, header::AUTHORIZATION, header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route(
            "/auth/register",
            post(controllers::register).options(cors_preflight),
        )
        .route(
            "/auth/verify-email",
            post(controllers::verify_email).options(cors_preflight),
        )
        .route(
            "/auth/resend-verification",
            post(controllers::resend_verification).options(cors_preflight),
        )
        .route(
            "/auth/forgot-password",
            post(controllers::forgot_password).options(cors_preflight),
        )
        .route(
            "/auth/reset-password",
            post(controllers::reset_password).options(cors_preflight),
        )
        .route(
            "/auth/login",
            post(controllers::login).options(cors_preflight),
        )
        .route(
            "/auth/mfa/send-email",
            post(controllers::send_email_mfa).options(cors_preflight),
        )
        .route(
            "/auth/mfa/verify-email",
            post(controllers::verify_email_mfa).options(cors_preflight),
        )
        .route(
            "/auth/mfa/verify-totp",
            post(controllers::verify_totp_mfa).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa",
            get(controllers::get_mfa_settings).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa/totp/setup",
            post(controllers::setup_totp).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa/totp/verify",
            post(controllers::verify_totp_setup).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa/email/setup",
            post(controllers::setup_email_mfa).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa/email/verify",
            post(controllers::verify_email_mfa_setup).options(cors_preflight),
        )
        .route(
            "/settings/security/mfa/disable",
            post(controllers::disable_mfa).options(cors_preflight),
        );
    app.with_state(state).layer(cors)
}

async fn cors_preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"status": "ok", "service": "bidmart-auth-be"}))
}

async fn ready_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(json!({"ready": true}))
}

#[cfg(test)]
mod contract_tests;
