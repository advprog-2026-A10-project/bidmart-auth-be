use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use chrono::Duration;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::modules::auth::application::use_cases::test_support::{
    fixed_now, sample_user, short_cooldown_policy, AuthUseCaseTestContext, FakeTokenHasher,
    UseCaseTestContext,
};
use crate::modules::auth::domain::entities::{AuthSession, UserStatus};
use crate::modules::auth::infrastructure::{create_router, AppState};

fn test_router(context: &UseCaseTestContext) -> axum::Router {
    let auth_context = AuthUseCaseTestContext::default();
    let app_state = AppState::new(
        Arc::new(context.register_use_case()),
        Arc::new(context.verify_email_use_case()),
        Arc::new(context.resend_verification_use_case()),
        Arc::new(auth_context.auth_mfa_use_case()),
        auth_context.jwt_issuer,
        auth_context.session_repository,
        auth_context.clock,
    );

    create_router(app_state)
}

fn auth_test_router(context: &AuthUseCaseTestContext) -> axum::Router {
    let base_context = UseCaseTestContext::default();
    let app_state = AppState::new(
        Arc::new(base_context.register_use_case()),
        Arc::new(base_context.verify_email_use_case()),
        Arc::new(base_context.resend_verification_use_case()),
        Arc::new(context.auth_mfa_use_case()),
        context.jwt_issuer.clone(),
        context.session_repository.clone(),
        context.clock.clone(),
    );

    create_router(app_state)
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("valid json response")
}

fn verified_auth_user(email: &str) -> crate::modules::auth::domain::entities::User {
    let now = fixed_now();
    let mut user = sample_user("Contract Auth", email, now);
    user.status = UserStatus::Active;
    user.email_verified_at = Some(now);
    user.password_hash = "hash::correct-password".to_string();
    user
}

fn seed_authenticated_session(context: &AuthUseCaseTestContext, user_id: uuid::Uuid) -> String {
    let token = format!("{user_id}:mfa");
    let now = fixed_now();
    let session = AuthSession {
        id: uuid::Uuid::new_v4(),
        user_id,
        jti_hash: FakeTokenHasher::deterministic_hash(&token),
        mfa_satisfied: true,
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    context
        .session_repository
        .state
        .lock()
        .expect("state lock poisoned")
        .sessions_by_hash
        .insert(session.jti_hash.clone(), session);
    token
}

#[tokio::test]
async fn post_register_returns_contract_success_shape() {
    let context = UseCaseTestContext::default();
    context
        .token_generator
        .push_token("contract-token-1".to_string());
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Alice Johnson",
                        "email": "alice@example.com",
                        "password": "StrongPassword123!"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("header"),
        "application/json"
    );

    let body = response_json(response).await;
    assert_eq!(
        body["message"],
        "Registration successful. Please verify your email."
    );
    assert_eq!(body["user"]["name"], "Alice Johnson");
    assert_eq!(body["user"]["email"], "alice@example.com");
    assert_eq!(body["user"]["emailVerified"], false);
    assert!(body["user"]["id"].as_str().is_some());
}

#[tokio::test]
async fn post_register_validation_failure_returns_422_error_envelope() {
    let context = UseCaseTestContext::default();
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "",
                        "email": "invalid-email",
                        "password": "123"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let body = response_json(response).await;
    assert_eq!(body["message"], "Validation error");
    assert_eq!(body["errors"]["name"][0], "Name is required");
    assert_eq!(
        body["errors"]["email"][0],
        "Email must be a valid email address"
    );
    assert_eq!(
        body["errors"]["password"][0],
        "Password must be at least 8 characters"
    );
}

#[tokio::test]
async fn post_verify_email_success_returns_message_payload() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("Verify Me", "verify.me@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "verify-contract-token",
        now - Duration::seconds(10),
        now + Duration::seconds(20),
    );
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify-email")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "token": "verify-contract-token" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body, json!({ "message": "Email verified." }));
}

#[tokio::test]
async fn post_verify_email_invalid_token_maps_to_400_json_envelope() {
    let context = UseCaseTestContext::default();
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify-email")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "token": "missing" }).to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body, json!({ "message": "Verification token invalid." }));
}

#[tokio::test]
async fn post_verify_email_expired_token_maps_to_410_json_envelope() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("Expired User", "expired@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "expired-contract-token",
        now - Duration::seconds(40),
        now - Duration::seconds(1),
    );
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify-email")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "token": "expired-contract-token" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::GONE);
    let body = response_json(response).await;
    assert_eq!(body, json!({ "message": "Verification token expired." }));
}

#[tokio::test]
async fn post_resend_verification_returns_expected_message_payload() {
    let context = UseCaseTestContext::default();
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/resend-verification")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": "missing@example.com" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(
        body,
        json!({
            "message": "If the account exists and requires verification, a verification email has been sent."
        })
    );
}

#[tokio::test]
async fn non_2xx_responses_use_json_error_envelope_for_resend_cooldown() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now).with_policy(short_cooldown_policy());
    let user = sample_user("Cooldown User", "cooldown@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "recent-token",
        now - Duration::seconds(5),
        now + Duration::seconds(20),
    );
    let app = test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/resend-verification")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": "cooldown@example.com" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(
        body,
        json!({
            "message": "Verification email was sent recently. Please wait before trying again."
        })
    );
}

#[tokio::test]
async fn post_login_verified_without_mfa_returns_access_token_contract() {
    let context = AuthUseCaseTestContext::default();
    let user = verified_auth_user("login@example.com");
    context.user_repository.insert_user(user);
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .jwt_issuer
        .queue_access_token("access.jwt".to_string(), "jti-login".to_string());
    let app = auth_test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "login@example.com",
                        "password": "correct-password"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body, json!({ "accessToken": "access.jwt" }));
}

#[tokio::test]
async fn post_login_mfa_enabled_returns_ticket_contract() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_auth_user("mfa-login@example.com");
    user.mfa_email_enabled = true;
    context.user_repository.insert_user(user);
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .token_generator
        .push_token("contract-mfa-ticket".to_string());
    let app = auth_test_router(&context);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "mfa-login@example.com",
                        "password": "correct-password"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["mfaTicket"], "contract-mfa-ticket");
    assert_eq!(body["methods"], json!(["email"]));
}

#[tokio::test]
async fn public_mfa_email_and_totp_endpoints_return_contract_shapes() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_auth_user("public-mfa@example.com");
    user.mfa_email_enabled = true;
    user.mfa_totp_enabled = true;
    user.mfa_totp_secret = Some("totp-secret".to_string());
    context.user_repository.insert_user(user.clone());
    context.seed_mfa_ticket(user.id, "send-ticket", fixed_now() + Duration::minutes(5));
    context.seed_mfa_ticket(user.id, "email-ticket", fixed_now() + Duration::minutes(5));
    context.seed_mfa_ticket(user.id, "totp-ticket", fixed_now() + Duration::minutes(5));
    context
        .totp_service
        .accept("totp-secret", "654321", fixed_now());
    context.token_generator.push_token("123456".to_string());
    context
        .jwt_issuer
        .queue_access_token("email.access.jwt".to_string(), "jti-email".to_string());
    context
        .jwt_issuer
        .queue_access_token("totp.access.jwt".to_string(), "jti-totp".to_string());
    let app = auth_test_router(&context);

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/mfa/send-email")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "mfaTicket": "send-ticket" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(send_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(send_response).await,
        json!({ "message": "MFA code sent." })
    );
    context.seed_email_mfa_code(
        user.id,
        "123456",
        fixed_now() - Duration::seconds(1),
        fixed_now() + Duration::minutes(5),
    );

    let email_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/mfa/verify-email")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "mfaTicket": "email-ticket", "code": "123456" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(email_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(email_response).await,
        json!({ "accessToken": "email.access.jwt" })
    );

    let totp_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/mfa/verify-totp")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "mfaTicket": "totp-ticket", "code": "654321" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(totp_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(totp_response).await,
        json!({ "accessToken": "totp.access.jwt" })
    );
}

#[tokio::test]
async fn protected_settings_mfa_endpoints_require_bearer_and_return_contracts() {
    let context = AuthUseCaseTestContext::default();
    let user = verified_auth_user("settings-contract@example.com");
    context.user_repository.insert_user(user.clone());
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .token_generator
        .push_token("setup-ticket".to_string());
    let bearer = seed_authenticated_session(&context, user.id);
    let app = auth_test_router(&context);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/settings/security/mfa")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let settings = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/settings/security/mfa")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(settings.status(), StatusCode::OK);
    assert_eq!(
        response_json(settings).await,
        json!({ "emailEnabled": false, "totpEnabled": false })
    );

    let totp_setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings/security/mfa/totp/setup")
                .header("authorization", format!("Bearer {bearer}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "currentPassword": "correct-password" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(totp_setup.status(), StatusCode::OK);
    let totp_setup_body = response_json(totp_setup).await;
    assert_eq!(totp_setup_body["setupTicket"], "setup-ticket");
    assert!(totp_setup_body["secret"].as_str().is_some());

    context
        .totp_service
        .accept("generated-totp-secret", "123456", fixed_now());

    let totp_verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings/security/mfa/totp/verify")
                .header("authorization", format!("Bearer {bearer}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "setupTicket": "setup-ticket",
                        "code": "123456",
                        "currentPassword": "correct-password"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(totp_verify.status(), StatusCode::OK);

    context.token_generator.push_token("444444".to_string());
    let email_setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings/security/mfa/email/setup")
                .header("authorization", format!("Bearer {bearer}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "currentPassword": "correct-password" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(email_setup.status(), StatusCode::OK);

    let email_verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings/security/mfa/email/verify")
                .header("authorization", format!("Bearer {bearer}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "code": "444444",
                        "currentPassword": "correct-password"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(email_verify.status(), StatusCode::OK);

    let disable = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings/security/mfa/disable")
                .header("authorization", format!("Bearer {bearer}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "currentPassword": "correct-password" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(disable.status(), StatusCode::OK);
}
