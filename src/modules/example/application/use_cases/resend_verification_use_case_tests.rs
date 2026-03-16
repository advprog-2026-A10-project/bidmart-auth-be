use chrono::Duration;

use crate::modules::auth::application::dto::ResendVerificationCommand;
use crate::modules::auth::application::use_cases::test_support::{
    fixed_now, sample_user, short_cooldown_policy, UseCaseTestContext,
};
use crate::modules::auth::domain::errors::AuthError;

#[tokio::test]
async fn resend_verification_succeeds_for_unverified_user_and_dispatches_email() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now).with_policy(short_cooldown_policy());
    let user = sample_user("Resend Ok", "resend.ok@example.com", now);
    context.user_repository.insert_user(user.clone());
    context
        .token_generator
        .push_token("fresh-resend-token".to_string());

    let use_case = context.resend_verification_use_case();
    let result = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;

    let resent = result.expect("resend should succeed");
    assert_eq!(
        resent.message,
        "If the account exists and requires verification, a verification email has been sent."
    );

    let email_state = context.email_sender.snapshot();
    assert_eq!(email_state.sent_messages.len(), 1);
    assert_eq!(email_state.sent_messages[0].0, user.email);
}

#[tokio::test]
async fn resend_verification_enforces_cooldown_window() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now).with_policy(short_cooldown_policy());
    let user = sample_user("Resend Cooldown", "resend.cooldown@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "still-hot-token",
        now - Duration::seconds(10),
        now + Duration::seconds(20),
    );

    let use_case = context.resend_verification_use_case();
    let result = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;

    assert_eq!(result, Err(AuthError::VerificationCooldownActive));
}

#[tokio::test]
async fn resend_verification_returns_generic_success_for_already_verified_user() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now);
    let mut user = sample_user(
        "Already Verified",
        "already.verified.resend@example.com",
        now,
    );
    user.email_verified_at = Some(now - Duration::seconds(5));
    context.user_repository.insert_user(user.clone());

    let use_case = context.resend_verification_use_case();
    let result = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;

    let resent = result.expect("already verified should return generic success");
    assert_eq!(
        resent.message,
        "If the account exists and requires verification, a verification email has been sent."
    );
    assert_eq!(context.email_sender.snapshot().sent_messages.len(), 0);
}

#[tokio::test]
async fn resend_verification_invalidates_old_active_tokens_before_issuing_new_token() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now).with_policy(short_cooldown_policy());
    let user = sample_user("Stale Token", "stale.token@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "stale-active-token",
        now - Duration::seconds(40),
        now + Duration::seconds(20),
    );
    context
        .token_generator
        .push_token("newly-issued-token".to_string());

    let use_case = context.resend_verification_use_case();
    let result = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;

    result.expect("resend should succeed");

    let token_state = context.token_repository.snapshot();
    assert_eq!(token_state.invalidate_calls.len(), 1);
    assert_eq!(token_state.saved_tokens.len(), 1);
}

#[tokio::test]
async fn resend_verification_behavior_depends_on_injected_clock_time() {
    let now = fixed_now();
    let context = UseCaseTestContext::new(now).with_policy(short_cooldown_policy());
    let user = sample_user("Clock Boundary", "clock.boundary@example.com", now);
    context.user_repository.insert_user(user.clone());
    context.seed_token_from_raw(
        user.id,
        "boundary-token",
        now - Duration::seconds(20),
        now + Duration::seconds(20),
    );

    let use_case = context.resend_verification_use_case();

    let first_attempt = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;
    assert_eq!(first_attempt, Err(AuthError::VerificationCooldownActive));

    context.clock.set_now(now + Duration::seconds(15));

    let second_attempt = use_case
        .execute(ResendVerificationCommand {
            email: user.email.clone(),
        })
        .await;
    second_attempt.expect("after cooldown boundary, resend should succeed");
}

#[tokio::test]
async fn resend_verification_returns_generic_success_for_unknown_email() {
    let context = UseCaseTestContext::default();
    let use_case = context.resend_verification_use_case();

    let result = use_case
        .execute(ResendVerificationCommand {
            email: "missing@example.com".to_string(),
        })
        .await;

    let resent = result.expect("unknown email should not leak account existence");
    assert_eq!(
        resent.message,
        "If the account exists and requires verification, a verification email has been sent."
    );
    assert_eq!(context.email_sender.snapshot().sent_messages.len(), 0);
}
