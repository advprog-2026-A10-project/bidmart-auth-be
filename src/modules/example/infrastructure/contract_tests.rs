use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use chrono::Duration;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::modules::auth::application::use_cases::test_support::{
    fixed_now, sample_user, short_cooldown_policy, UseCaseTestContext,
};
use crate::modules::auth::infrastructure::{create_router, AppState};

fn test_router(context: &UseCaseTestContext) -> axum::Router {
    let app_state = AppState::new(
        Arc::new(context.register_use_case()),
        Arc::new(context.verify_email_use_case()),
        Arc::new(context.resend_verification_use_case()),
    );

    create_router(app_state)
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("valid json response")
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
