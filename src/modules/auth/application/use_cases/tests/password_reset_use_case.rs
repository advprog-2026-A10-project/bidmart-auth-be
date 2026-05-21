use chrono::Duration;

use crate::modules::auth::application::dto::{
    ForgotPasswordCommand, ResetPasswordCommand, FORGOT_PASSWORD_MESSAGE,
    RESET_PASSWORD_SUCCESS_MESSAGE,
};
use crate::modules::auth::domain::entities::{AuthSession, UserStatus};
use crate::modules::auth::domain::errors::AuthError;

use super::support::{
    fixed_now, sample_user, AuthUseCaseTestContext, FakeTokenHasher, UseCaseTestContext,
};

fn active_user(name: &str, email: &str) -> crate::modules::auth::domain::entities::User {
    let now = fixed_now();
    let mut user = sample_user(name, email, now);
    user.status = UserStatus::Active;
    user.email_verified_at = Some(now);
    user
}

#[tokio::test]
async fn forgot_password_sends_reset_email_for_existing_verified_user() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset User", "reset@example.com");
    context.user_repository.insert_user(user.clone());
    context
        .token_generator
        .push_token("raw-reset-token".to_string());

    let result = context
        .forgot_password_use_case()
        .execute(ForgotPasswordCommand {
            email: " RESET@EXAMPLE.COM ".to_string(),
        })
        .await
        .expect("forgot password should succeed");

    assert_eq!(result.message, FORGOT_PASSWORD_MESSAGE);
    assert_eq!(
        context.email_sender.snapshot().sent_password_resets,
        vec![(
            "reset@example.com".to_string(),
            "raw-reset-token".to_string()
        )]
    );
    let token_state = context.password_reset_token_repository.snapshot();
    assert_eq!(token_state.saved_tokens.len(), 1);
    assert_eq!(token_state.saved_tokens[0].user_id, user.id);
    assert_eq!(
        token_state.saved_tokens[0].token_hash,
        FakeTokenHasher::deterministic_hash("raw-reset-token")
    );
}

#[tokio::test]
async fn forgot_password_returns_generic_success_when_email_sender_fails() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Sender Failure", "reset.sender.failure@example.com");
    context.user_repository.insert_user(user.clone());
    context
        .token_generator
        .push_token("raw-reset-token".to_string());
    *context
        .email_sender
        .send_error
        .lock()
        .expect("error lock poisoned") = Some(AuthError::DependencyFailure(
        "smtp transport error".to_string(),
    ));

    let result = context
        .forgot_password_use_case()
        .execute(ForgotPasswordCommand {
            email: user.email.clone(),
        })
        .await
        .expect("forgot password should still return generic success");

    assert_eq!(result.message, FORGOT_PASSWORD_MESSAGE);
    assert!(context
        .email_sender
        .snapshot()
        .sent_password_resets
        .is_empty());
    assert_eq!(
        context
            .password_reset_token_repository
            .snapshot()
            .saved_tokens
            .len(),
        1
    );
}

#[tokio::test]
async fn forgot_password_returns_generic_success_for_unknown_email_without_sending() {
    let context = UseCaseTestContext::default();

    let result = context
        .forgot_password_use_case()
        .execute(ForgotPasswordCommand {
            email: "missing@example.com".to_string(),
        })
        .await
        .expect("unknown email should not leak account existence");

    assert_eq!(result.message, FORGOT_PASSWORD_MESSAGE);
    assert!(context
        .email_sender
        .snapshot()
        .sent_password_resets
        .is_empty());
    assert!(context
        .password_reset_token_repository
        .snapshot()
        .saved_tokens
        .is_empty());
}

#[tokio::test]
async fn forgot_password_enforces_reset_email_cooldown() {
    let context = UseCaseTestContext::default();
    let user = active_user("Cooldown User", "cooldown@example.com");
    context.user_repository.insert_user(user.clone());
    context.seed_password_reset_token_from_raw(
        user.id,
        "recent-reset-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );

    let result = context
        .forgot_password_use_case()
        .execute(ForgotPasswordCommand {
            email: "cooldown@example.com".to_string(),
        })
        .await
        .expect("cooldown should not leak account existence");

    assert_eq!(result.message, FORGOT_PASSWORD_MESSAGE);
    assert!(context
        .email_sender
        .snapshot()
        .sent_password_resets
        .is_empty());
}

#[tokio::test]
async fn reset_password_with_valid_token_hashes_new_password_consumes_token_and_updates_user() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Success", "reset.success@example.com");
    context.user_repository.insert_user(user.clone());
    let token = context.seed_password_reset_token_from_raw(
        user.id,
        "valid-reset-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );

    let result = context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "valid-reset-token".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await
        .expect("reset should succeed");

    assert_eq!(result.message, RESET_PASSWORD_SUCCESS_MESSAGE);
    assert_eq!(
        context.password_hasher.snapshot().hash_calls,
        vec!["NewPassword123!".to_string()]
    );
    let user_state = context.user_repository.snapshot();
    let updated = user_state.users_by_id.get(&user.id).expect("user updated");
    assert_eq!(updated.password_hash, "hashed::NewPassword123!");
    assert_eq!(
        context
            .password_reset_token_repository
            .snapshot()
            .consume_calls,
        vec![(token.id, fixed_now())]
    );
}

#[tokio::test]
async fn reset_password_revokes_active_sessions_for_user() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Sessions", "reset.sessions@example.com");
    context.user_repository.insert_user(user.clone());
    context.seed_password_reset_token_from_raw(
        user.id,
        "valid-reset-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );
    context.session_repository.insert_session(AuthSession {
        id: uuid::Uuid::new_v4(),
        user_id: user.id,
        jti_hash: "active-session".to_string(),
        mfa_satisfied: true,
        device: "Test device".to_string(),
        browser: "Test browser".to_string(),
        os: "Test OS".to_string(),
        ip: "127.0.0.1".to_string(),
        location: "Test location".to_string(),
        created_at: fixed_now(),
        last_active_at: fixed_now(),
        expires_at: fixed_now() + Duration::hours(1),
    });

    context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "valid-reset-token".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await
        .expect("reset should succeed");

    let session_state = context.session_repository.snapshot();
    assert_eq!(session_state.revoke_calls, vec![(user.id, fixed_now())]);
    assert_eq!(
        session_state
            .sessions_by_hash
            .get("active-session")
            .expect("session exists")
            .expires_at,
        fixed_now()
    );
}

#[tokio::test]
async fn reset_password_does_not_consume_token_when_password_update_fails() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Update Failure", "reset.update.failure@example.com");
    context.user_repository.insert_user(user.clone());
    let token = context.seed_password_reset_token_from_raw(
        user.id,
        "valid-reset-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );
    *context
        .user_repository
        .update_password_hash_error
        .lock()
        .expect("error lock poisoned") = Some(AuthError::DependencyFailure(
        "password update failed".to_string(),
    ));

    let result = context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "valid-reset-token".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await;

    assert_eq!(
        result,
        Err(AuthError::DependencyFailure(
            "password update failed".to_string()
        ))
    );
    let token_state = context.password_reset_token_repository.snapshot();
    assert!(!token_state.consume_calls.contains(&(token.id, fixed_now())));
    assert!(token_state
        .tokens_by_hash
        .values()
        .all(|token| token.consumed_at.is_none()));
}

#[tokio::test]
async fn reset_password_session_revoke_failure_rolls_back_token_and_password_changes() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Revoke Failure", "reset.revoke.failure@example.com");
    context.user_repository.insert_user(user.clone());
    context.seed_password_reset_token_from_raw(
        user.id,
        "valid-reset-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );
    context.session_repository.insert_session(AuthSession {
        id: uuid::Uuid::new_v4(),
        user_id: user.id,
        jti_hash: "active-session".to_string(),
        mfa_satisfied: true,
        device: "Test device".to_string(),
        browser: "Test browser".to_string(),
        os: "Test OS".to_string(),
        ip: "127.0.0.1".to_string(),
        location: "Test location".to_string(),
        created_at: fixed_now(),
        last_active_at: fixed_now(),
        expires_at: fixed_now() + Duration::hours(1),
    });
    *context
        .session_repository
        .revoke_error
        .lock()
        .expect("error lock poisoned") = Some(AuthError::DependencyFailure(
        "session revoke failed".to_string(),
    ));

    let result = context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "valid-reset-token".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await;

    assert_eq!(
        result,
        Err(AuthError::DependencyFailure(
            "session revoke failed".to_string()
        ))
    );
    assert!(context
        .password_reset_token_repository
        .snapshot()
        .tokens_by_hash
        .values()
        .all(|token| token.consumed_at.is_none()));
    assert_eq!(
        context
            .user_repository
            .snapshot()
            .users_by_id
            .get(&user.id)
            .expect("user exists")
            .password_hash,
        user.password_hash
    );
    assert_eq!(
        context
            .session_repository
            .snapshot()
            .sessions_by_hash
            .get("active-session")
            .expect("session exists")
            .expires_at,
        fixed_now() + Duration::hours(1)
    );
}

#[tokio::test]
async fn reset_password_rejects_invalid_expired_and_used_tokens() {
    let context = UseCaseTestContext::default();
    let user = active_user("Reset Errors", "reset.errors@example.com");
    context.user_repository.insert_user(user.clone());

    let expired = context.seed_password_reset_token_from_raw(
        user.id,
        "expired-token",
        fixed_now() - Duration::minutes(20),
        fixed_now() - Duration::minutes(1),
    );
    let mut used = context.seed_password_reset_token_from_raw(
        user.id,
        "used-token",
        fixed_now(),
        fixed_now() + Duration::minutes(15),
    );
    used.consumed_at = Some(fixed_now());
    context
        .password_reset_token_repository
        .insert_token(used.clone());

    let use_case = context.reset_password_use_case();

    assert_eq!(
        use_case
            .execute(ResetPasswordCommand {
                token: "missing-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await,
        Err(AuthError::PasswordResetTokenInvalid)
    );
    assert_eq!(
        use_case
            .execute(ResetPasswordCommand {
                token: "expired-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await,
        Err(AuthError::PasswordResetTokenExpired)
    );
    assert_eq!(
        use_case
            .execute(ResetPasswordCommand {
                token: "used-token".to_string(),
                password: "NewPassword123!".to_string(),
            })
            .await,
        Err(AuthError::PasswordResetTokenAlreadyUsed)
    );
    assert!(!context
        .password_reset_token_repository
        .snapshot()
        .consume_calls
        .contains(&(expired.id, fixed_now())));
}

#[tokio::test]
async fn reset_password_rejects_blank_token_after_trimming() {
    let context = UseCaseTestContext::default();

    let result = context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "   ".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::PasswordResetTokenInvalid));
    assert!(context.token_hasher.snapshot().hash_calls.is_empty());
}

#[tokio::test]
async fn reset_password_trims_token_before_hash_lookup() {
    let context = UseCaseTestContext::default();
    let user = active_user("Trim Reset", "trim.reset@example.com");
    context.user_repository.insert_user(user.clone());
    context.seed_password_reset_token_from_raw(
        user.id,
        "trim-reset-token",
        fixed_now() - Duration::minutes(1),
        fixed_now() + Duration::minutes(1),
    );

    let result = context
        .reset_password_use_case()
        .execute(ResetPasswordCommand {
            token: "  trim-reset-token  ".to_string(),
            password: "NewPassword123!".to_string(),
        })
        .await;

    result.expect("reset should succeed with trimmed token");
    assert_eq!(
        context.token_hasher.snapshot().hash_calls,
        vec!["trim-reset-token".to_string()]
    );
}

#[tokio::test]
async fn login_contract_returns_user_with_access_token_or_mfa_ticket_shape() {
    let context = AuthUseCaseTestContext::default();
    let mut user = active_user("Login Contract", "login.contract@example.com");
    user.password_hash = "hash::correct-password".to_string();
    context.user_repository.insert_user(user.clone());
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .jwt_issuer
        .queue_access_token("access.jwt".to_string(), "jti-login".to_string());

    let login = context
        .auth_mfa_use_case()
        .login(
            crate::modules::auth::application::dto::LoginCommand {
                email: "login.contract@example.com".to_string(),
                password: "correct-password".to_string(),
            },
            crate::modules::auth::application::dto::SessionContext::unknown(),
        )
        .await
        .expect("login should succeed");

    match login {
        crate::modules::auth::application::dto::LoginOutcome::Authenticated(result) => {
            assert_eq!(result.access_token, "access.jwt");
            assert_eq!(result.email, "login.contract@example.com");
            assert_eq!(result.name, "Login Contract");
        }
        _ => panic!("expected authenticated login"),
    }

    let mut mfa_user = active_user("Mfa Contract", "mfa.contract@example.com");
    mfa_user.password_hash = "hash::mfa-password".to_string();
    mfa_user.mfa_totp_enabled = true;
    mfa_user.mfa_totp_secret = Some("totp-secret".to_string());
    context.user_repository.insert_user(mfa_user);
    context
        .password_verifier
        .accept("mfa-password", "hash::mfa-password");
    context.token_generator.push_token("mfa-ticket".to_string());

    let login = context
        .auth_mfa_use_case()
        .login(
            crate::modules::auth::application::dto::LoginCommand {
                email: "mfa.contract@example.com".to_string(),
                password: "mfa-password".to_string(),
            },
            crate::modules::auth::application::dto::SessionContext::unknown(),
        )
        .await
        .expect("mfa login should produce ticket");

    assert_eq!(
        login,
        crate::modules::auth::application::dto::LoginOutcome::MfaRequired {
            mfa_ticket: "mfa-ticket".to_string(),
            mfa_type: "totp".to_string()
        }
    );
}
