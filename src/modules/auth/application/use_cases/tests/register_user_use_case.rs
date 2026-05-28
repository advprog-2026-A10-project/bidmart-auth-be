use crate::modules::auth::application::dto::RegisterUserCommand;
use crate::modules::auth::domain::errors::AuthError;

use super::support::{fixed_now, sample_user, short_cooldown_policy, UseCaseTestContext};

fn normalized_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

#[tokio::test]
async fn successful_registration_creates_an_unverified_user() {
    let context = UseCaseTestContext::default().with_policy(short_cooldown_policy());
    context
        .token_generator
        .push_token("verify-token-001".to_string());

    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "New User".to_string(),
            email: "new.user@example.com".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    let registered = result.expect("registration should succeed");
    assert!(!registered.email_verified);
    assert_eq!(registered.name, "New User");

    let state = context.user_repository.snapshot();
    assert_eq!(state.created_users.len(), 1);
    assert!(state.created_users[0].email_verified_at.is_none());
    assert_eq!(state.created_users[0].display_name(), "New User");
}

#[tokio::test]
async fn registration_never_stores_plaintext_password() {
    let context = UseCaseTestContext::default();
    let use_case = context.register_use_case();
    let raw_password = "UnsafePlaintext123!";

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Security Check".to_string(),
            email: "security.check@example.com".to_string(),
            password: raw_password.to_string(),
        })
        .await;

    result.expect("registration should succeed");

    let state = context.user_repository.snapshot();
    assert_eq!(state.created_users.len(), 1);
    assert_ne!(state.created_users[0].password_hash, raw_password);
    assert_eq!(
        context.password_hasher.snapshot().hash_calls,
        vec![raw_password.to_string()]
    );
}

#[tokio::test]
async fn registration_generates_verification_token_and_persists_it() {
    let context = UseCaseTestContext::default();
    context
        .token_generator
        .push_token("verify-token-002".to_string());
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Token Create".to_string(),
            email: "token.create@example.com".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    result.expect("registration should succeed");

    let token_generator_state = context.token_generator.snapshot();
    assert_eq!(token_generator_state.generate_calls, 1);

    let token_repo_state = context.token_repository.snapshot();
    assert_eq!(token_repo_state.saved_tokens.len(), 1);
}

#[tokio::test]
async fn registration_requests_verification_email_dispatch() {
    let context = UseCaseTestContext::default();
    context
        .token_generator
        .push_token("verify-token-003".to_string());
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Dispatch User".to_string(),
            email: "dispatch@example.com".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    result.expect("registration should succeed");

    let email_state = context.email_sender.snapshot();
    assert_eq!(email_state.sent_messages.len(), 1);
    assert_eq!(email_state.sent_messages[0].0, "dispatch@example.com");
    assert_eq!(email_state.sent_messages[0].1, "verify-token-003");
}

#[tokio::test]
async fn registration_rejects_invalid_email() {
    let context = UseCaseTestContext::default();
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Invalid Email".to_string(),
            email: "invalid-email".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::InvalidEmail));
}

#[tokio::test]
async fn registration_rejects_weak_password_by_policy() {
    let context = UseCaseTestContext::default();
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Weak Password".to_string(),
            email: "weak.password@example.com".to_string(),
            password: "123".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::WeakPassword));
}

#[tokio::test]
async fn registration_rejects_duplicate_email_after_normalization() {
    let context = UseCaseTestContext::default();
    let existing = sample_user("Dupe User", "dupe@example.com", fixed_now());
    context.user_repository.insert_user(existing);
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Duplicate User".to_string(),
            email: "  DUPE@example.com ".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::EmailAlreadyExists));
}

#[tokio::test]
async fn registration_applies_consistent_email_normalization_for_lookup_and_persistence() {
    let context = UseCaseTestContext::default();
    let use_case = context.register_use_case();
    let input_email = "  MiXeD.Case+tag@Example.COM ";

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Mixed Case".to_string(),
            email: input_email.to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    result.expect("registration should succeed");

    let user_state = context.user_repository.snapshot();
    assert_eq!(user_state.find_by_email_inputs.len(), 1);
    assert_eq!(
        user_state.find_by_email_inputs[0],
        normalized_email(input_email)
    );
    assert_eq!(user_state.created_users.len(), 1);
    assert_eq!(
        user_state.created_users[0].email,
        normalized_email(input_email)
    );
}

#[tokio::test]
async fn registration_result_matches_public_contract_fields() {
    let context = UseCaseTestContext::default();
    let use_case = context.register_use_case();

    let result = use_case
        .execute(RegisterUserCommand {
            name: "Alice Johnson".to_string(),
            email: "alice@example.com".to_string(),
            password: "StrongPassword123!".to_string(),
        })
        .await;

    let registered = result.expect("registration should succeed");
    assert_eq!(registered.name, "Alice Johnson");
    assert_eq!(registered.email, "alice@example.com");
    assert!(!registered.email_verified);
}
