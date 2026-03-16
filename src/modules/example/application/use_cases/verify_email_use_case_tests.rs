use chrono::Duration;

use crate::modules::example::application::dto::VerifyEmailCommand;
use crate::modules::example::application::use_cases::test_support::{
    fixed_now, sample_user, UseCaseTestContext,
};
use crate::modules::example::domain::errors::AuthError;

#[tokio::test]
async fn verify_email_with_valid_token_marks_user_verified_and_consumes_token() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("verify.ok@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "valid-token",
        now - Duration::minutes(1),
        now + Duration::minutes(14),
    );

    let use_case = context.verify_email_use_case();
    let result = use_case
        .execute(VerifyEmailCommand {
            token: "valid-token".to_string(),
        })
        .await;

    result.expect("verification should succeed");

    let user_state = context.user_repository.snapshot();
    assert_eq!(user_state.mark_email_verified_calls.len(), 1);

    let token_state = context.token_repository.snapshot();
    assert_eq!(token_state.consume_calls.len(), 1);
}

#[tokio::test]
async fn verify_email_rejects_invalid_token() {
    let context = UseCaseTestContext::default();
    let use_case = context.verify_email_use_case();

    let result = use_case
        .execute(VerifyEmailCommand {
            token: "unknown-token".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::VerificationTokenInvalid));
}

#[tokio::test]
async fn verify_email_rejects_expired_token() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("expired.token@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "expired-token",
        now - Duration::minutes(20),
        now - Duration::seconds(1),
    );

    let use_case = context.verify_email_use_case();
    let result = use_case
        .execute(VerifyEmailCommand {
            token: "expired-token".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::VerificationTokenExpired));
}

#[tokio::test]
async fn verify_email_rejects_already_used_token() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("used.token@example.com", now);
    context.user_repository.insert_user(user.clone());
    let mut used = context.seed_token_from_raw(
        user.id,
        "already-used-token",
        now - Duration::minutes(2),
        now + Duration::minutes(13),
    );
    used.consumed_at = Some(now - Duration::minutes(1));
    context.token_repository.insert_token(used);

    let use_case = context.verify_email_use_case();
    let result = use_case
        .execute(VerifyEmailCommand {
            token: "already-used-token".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::VerificationTokenAlreadyUsed));
}

#[tokio::test]
async fn verify_email_rejects_when_user_is_already_verified() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let mut user = sample_user("already.verified@example.com", now);
    user.email_verified_at = Some(now - Duration::minutes(10));
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "token-for-verified-user",
        now - Duration::minutes(1),
        now + Duration::minutes(14),
    );

    let use_case = context.verify_email_use_case();
    let result = use_case
        .execute(VerifyEmailCommand {
            token: "token-for-verified-user".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::UserAlreadyVerified));
}

#[tokio::test]
async fn verify_email_must_hash_raw_token_before_lookup() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let user = sample_user("hash.lookup@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "hash-lookup-token",
        now - Duration::minutes(1),
        now + Duration::minutes(14),
    );

    let use_case = context.verify_email_use_case();
    let result = use_case
        .execute(VerifyEmailCommand {
            token: "hash-lookup-token".to_string(),
        })
        .await;

    result.expect("verification should succeed");

    let hasher_state = context.token_hasher.snapshot();
    assert_eq!(
        hasher_state.hash_calls,
        vec!["hash-lookup-token".to_string()]
    );

    let token_state = context.token_repository.snapshot();
    assert_eq!(token_state.find_by_hash_inputs.len(), 1);
    assert_eq!(
        token_state.find_by_hash_inputs[0],
        "token-hash::hash-lookup-token"
    );
}
