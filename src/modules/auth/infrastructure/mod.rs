use std::sync::Arc;

use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::json;
use tower_http::cors::CorsLayer;

use crate::infrastructure::amqp::AmqpPublisher;
use crate::infrastructure::logger::request_trace_middleware;
use crate::modules::auth::application::use_cases::auth_mfa_use_case::AuthMfaUseCase;
use crate::modules::auth::application::use_cases::mfa_setup_use_case::MfaSetupUseCase;
use crate::modules::auth::application::use_cases::notification_use_case::NotificationUseCase;
use crate::modules::auth::application::use_cases::password_reset_use_case::{
    ForgotPasswordUseCase, ResetPasswordUseCase,
};
use crate::modules::auth::application::use_cases::profile_use_case::ProfileUseCase;
use crate::modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use crate::modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use crate::modules::auth::application::use_cases::session_use_case::SessionUseCase;
use crate::modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use crate::modules::auth::domain::traits::AuthorizationRepository;

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub verify_email_use_case: Arc<VerifyEmailUseCase>,
    pub resend_verification_use_case: Arc<ResendVerificationUseCase>,
    pub forgot_password_use_case: Arc<ForgotPasswordUseCase>,
    pub reset_password_use_case: Arc<ResetPasswordUseCase>,
    pub auth_mfa_use_case: Arc<AuthMfaUseCase>,
    pub profile_use_case: Arc<ProfileUseCase>,
    pub session_use_case: Arc<SessionUseCase>,
    pub authorization_repository: Arc<dyn AuthorizationRepository>,
    pub mfa_setup_use_case: Arc<MfaSetupUseCase>,
    pub notification_use_case: Arc<NotificationUseCase>,
    pub session_cookie_name: String,
    pub session_cookie_secure: bool,
    pub session_cookie_same_site: String,
    pub session_cookie_domain: Option<String>,
    pub session_cookie_max_age_seconds: i64,
    pub amqp: Option<AmqpPublisher>,
    pub internal_service_token: Option<String>,
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
        profile_use_case: Arc<ProfileUseCase>,
        session_use_case: Arc<SessionUseCase>,
        authorization_repository: Arc<dyn AuthorizationRepository>,
        mfa_setup_use_case: Arc<MfaSetupUseCase>,
        notification_use_case: Arc<NotificationUseCase>,
        session_cookie_name: String,
        session_cookie_secure: bool,
        session_cookie_same_site: String,
        session_cookie_domain: Option<String>,
        session_cookie_max_age_seconds: i64,
        amqp: Option<AmqpPublisher>,
        internal_service_token: Option<String>,
    ) -> Self {
        Self {
            register_use_case,
            verify_email_use_case,
            resend_verification_use_case,
            forgot_password_use_case,
            reset_password_use_case,
            auth_mfa_use_case,
            profile_use_case,
            session_use_case,
            authorization_repository,
            mfa_setup_use_case,
            notification_use_case,
            session_cookie_name,
            session_cookie_secure,
            session_cookie_same_site,
            session_cookie_domain,
            session_cookie_max_age_seconds,
            amqp,
            internal_service_token,
        }
    }
}

pub mod auth_extractor;
pub mod controllers;
pub mod repositories;
pub mod services;
pub mod session_cookie;

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
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-request-id"),
        ]);

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
            "/auth/logout",
            post(controllers::logout).options(cors_preflight),
        )
        .route(
            "/auth/validate",
            post(controllers::validate_session).options(cors_preflight),
        )
        .route(
            "/auth/me",
            get(controllers::validate_session).options(cors_preflight),
        )
        .route(
            "/internal/users/{user_id}/roles/assign",
            post(controllers::assign_user_role).options(cors_preflight),
        )
        .route(
            "/internal/users/{user_id}/roles/revoke",
            post(controllers::revoke_user_role).options(cors_preflight),
        )
        .route(
            "/internal/roles/{role_name}/permissions/assign",
            post(controllers::assign_role_permission).options(cors_preflight),
        )
        .route(
            "/internal/roles/{role_name}/permissions/revoke",
            post(controllers::revoke_role_permission).options(cors_preflight),
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
            "/settings/profile",
            get(controllers::get_profile)
                .put(controllers::update_profile)
                .options(cors_preflight),
        )
        .route(
            "/settings/security/password",
            post(controllers::change_password).options(cors_preflight),
        )
        .route(
            "/settings/security/sessions",
            get(controllers::get_sessions)
                .delete(controllers::revoke_all_sessions)
                .options(cors_preflight),
        )
        .route(
            "/settings/security/sessions/{session_id}",
            delete(controllers::revoke_session).options(cors_preflight),
        )
        .route(
            "/settings/notifications",
            get(controllers::get_notification_preferences)
                .put(controllers::update_notification_preferences)
                .options(cors_preflight),
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
    app.with_state(state)
        .layer(middleware::from_fn(request_trace_middleware))
        .layer(cors)
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
mod tests;
