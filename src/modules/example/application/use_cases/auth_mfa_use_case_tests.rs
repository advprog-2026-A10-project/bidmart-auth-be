use chrono::Duration;

use crate::modules::auth::application::dto::{
    AuthenticatedUserContext, DisableMfaCommand, LoginCommand, LoginOutcome, SendEmailMfaCommand,
    SetupEmailMfaCommand, SetupTotpCommand, VerifyEmailMfaCommand, VerifyEmailMfaSetupCommand,
    VerifyTotpMfaCommand, VerifyTotpSetupCommand,
};
use crate::modules::auth::application::use_cases::test_support::{
    fixed_now, sample_user, AuthUseCaseTestContext,
};
use crate::modules::auth::domain::entities::UserStatus;
use crate::modules::auth::domain::errors::AuthError;

fn verified_user(email: &str) -> crate::modules::auth::domain::entities::User {
    let now = fixed_now();
    let mut user = sample_user("Auth User", email, now);
    user.status = UserStatus::Active;
    user.email_verified_at = Some(now);
    user.password_hash = "hash::correct-password".to_string();
    user
}

#[tokio::test]
async fn login_rejects_unverified_user_without_issuing_jwt() {
    let context = AuthUseCaseTestContext::default();
    let mut user = sample_user("Pending User", "pending@example.com", fixed_now());
    user.password_hash = "hash::correct-password".to_string();
    context.user_repository.insert_user(user);
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");

    let result = context
        .auth_mfa_use_case()
        .login(LoginCommand {
            email: " Pending@Example.com ".to_string(),
            password: "correct-password".to_string(),
        })
        .await;

    assert_eq!(result, Err(AuthError::EmailNotVerified));
    assert!(context
        .jwt_issuer
        .snapshot()
        .issued_access_tokens
        .is_empty());
}

#[tokio::test]
async fn login_bad_credentials_are_generic_for_missing_user_and_bad_password() {
    let context = AuthUseCaseTestContext::default();
    let user = verified_user("known@example.com");
    context.user_repository.insert_user(user);
    context
        .password_verifier
        .reject("wrong-password", "hash::correct-password");

    let missing = context
        .auth_mfa_use_case()
        .login(LoginCommand {
            email: "missing@example.com".to_string(),
            password: "whatever-password".to_string(),
        })
        .await;
    let wrong_password = context
        .auth_mfa_use_case()
        .login(LoginCommand {
            email: "known@example.com".to_string(),
            password: "wrong-password".to_string(),
        })
        .await;

    assert_eq!(missing, Err(AuthError::InvalidCredentials));
    assert_eq!(wrong_password, Err(AuthError::InvalidCredentials));
}

#[tokio::test]
async fn login_for_verified_user_without_mfa_issues_access_token_and_persists_session() {
    let context = AuthUseCaseTestContext::default();
    let user = verified_user("verified@example.com");
    context.user_repository.insert_user(user.clone());
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .jwt_issuer
        .queue_access_token("access.jwt".to_string(), "jti-1".to_string());

    let result = context
        .auth_mfa_use_case()
        .login(LoginCommand {
            email: "verified@example.com".to_string(),
            password: "correct-password".to_string(),
        })
        .await
        .expect("login succeeds");

    assert_eq!(
        result,
        LoginOutcome::Authenticated {
            access_token: "access.jwt".to_string()
        }
    );
    assert_eq!(
        context.session_repository.snapshot().saved_sessions.len(),
        1
    );
    assert_eq!(
        context.session_repository.snapshot().saved_sessions[0].user_id,
        user.id
    );
}

#[tokio::test]
async fn login_for_mfa_enabled_user_issues_scoped_mfa_ticket_only() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_user("mfa@example.com");
    user.mfa_email_enabled = true;
    context.user_repository.insert_user(user);
    context
        .password_verifier
        .accept("correct-password", "hash::correct-password");
    context
        .token_generator
        .push_token("raw-mfa-ticket".to_string());

    let result = context
        .auth_mfa_use_case()
        .login(LoginCommand {
            email: "mfa@example.com".to_string(),
            password: "correct-password".to_string(),
        })
        .await
        .expect("login returns mfa challenge");

    assert_eq!(
        result,
        LoginOutcome::MfaRequired {
            mfa_ticket: "raw-mfa-ticket".to_string(),
            methods: vec!["email".to_string()]
        }
    );
    assert!(context
        .jwt_issuer
        .snapshot()
        .issued_access_tokens
        .is_empty());
    assert_eq!(
        context.mfa_ticket_repository.snapshot().saved_tickets.len(),
        1
    );
}

#[tokio::test]
async fn email_mfa_send_enforces_cooldown_and_code_expiry() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_user("mfa-code@example.com");
    user.mfa_email_enabled = true;
    context.user_repository.insert_user(user.clone());
    context.seed_mfa_ticket(user.id, "ticket", fixed_now() + Duration::minutes(5));
    context.token_generator.push_token("654321".to_string());

    context
        .auth_mfa_use_case()
        .send_email_mfa(SendEmailMfaCommand {
            mfa_ticket: "ticket".to_string(),
        })
        .await
        .expect("first send succeeds");

    let cooldown = context
        .auth_mfa_use_case()
        .send_email_mfa(SendEmailMfaCommand {
            mfa_ticket: "ticket".to_string(),
        })
        .await;

    assert_eq!(cooldown, Err(AuthError::MfaCodeCooldownActive));
    let code = context.email_mfa_code_repository.snapshot().saved_codes[0].clone();
    assert_eq!(
        code.expires_at,
        fixed_now() + context.policy.email_mfa_code_ttl
    );
}

#[tokio::test]
async fn email_mfa_verify_success_invalid_expired_and_replay_are_enforced() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_user("email-verify@example.com");
    user.mfa_email_enabled = true;
    context.user_repository.insert_user(user.clone());
    context.seed_mfa_ticket(user.id, "ticket", fixed_now() + Duration::minutes(5));
    context.seed_email_mfa_code(
        user.id,
        "123456",
        fixed_now() - Duration::seconds(1),
        fixed_now() + Duration::minutes(5),
    );
    context
        .jwt_issuer
        .queue_access_token("mfa.access.jwt".to_string(), "jti-mfa".to_string());

    let success = context
        .auth_mfa_use_case()
        .verify_email_mfa(VerifyEmailMfaCommand {
            mfa_ticket: "ticket".to_string(),
            code: "123456".to_string(),
        })
        .await
        .expect("email mfa succeeds");
    assert_eq!(success.access_token, "mfa.access.jwt");

    let replay = context
        .auth_mfa_use_case()
        .verify_email_mfa(VerifyEmailMfaCommand {
            mfa_ticket: "ticket".to_string(),
            code: "123456".to_string(),
        })
        .await;
    assert_eq!(replay, Err(AuthError::MfaTicketInvalid));

    context.seed_mfa_ticket(
        user.id,
        "expired-ticket",
        fixed_now() - Duration::seconds(1),
    );
    let expired = context
        .auth_mfa_use_case()
        .verify_email_mfa(VerifyEmailMfaCommand {
            mfa_ticket: "expired-ticket".to_string(),
            code: "123456".to_string(),
        })
        .await;
    assert_eq!(expired, Err(AuthError::MfaTicketExpired));

    context.seed_mfa_ticket(
        user.id,
        "invalid-code-ticket",
        fixed_now() + Duration::minutes(5),
    );
    let invalid = context
        .auth_mfa_use_case()
        .verify_email_mfa(VerifyEmailMfaCommand {
            mfa_ticket: "invalid-code-ticket".to_string(),
            code: "999999".to_string(),
        })
        .await;
    assert_eq!(invalid, Err(AuthError::MfaCodeInvalid));
}

#[tokio::test]
async fn totp_mfa_verify_success_invalid_expired_and_replay_are_enforced() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_user("totp-login@example.com");
    user.mfa_totp_enabled = true;
    user.mfa_totp_secret = Some("totp-secret".to_string());
    context.user_repository.insert_user(user.clone());
    context.seed_mfa_ticket(user.id, "totp-ticket", fixed_now() + Duration::minutes(5));
    context
        .totp_service
        .accept("totp-secret", "123456", fixed_now());
    context
        .jwt_issuer
        .queue_access_token("totp.access.jwt".to_string(), "jti-totp".to_string());

    let success = context
        .auth_mfa_use_case()
        .verify_totp_mfa(VerifyTotpMfaCommand {
            mfa_ticket: "totp-ticket".to_string(),
            code: "123456".to_string(),
        })
        .await
        .expect("totp mfa succeeds");
    assert_eq!(success.access_token, "totp.access.jwt");

    let replay = context
        .auth_mfa_use_case()
        .verify_totp_mfa(VerifyTotpMfaCommand {
            mfa_ticket: "totp-ticket".to_string(),
            code: "123456".to_string(),
        })
        .await;
    assert_eq!(replay, Err(AuthError::MfaTicketInvalid));

    context.seed_mfa_ticket(
        user.id,
        "bad-totp-ticket",
        fixed_now() + Duration::minutes(5),
    );
    let invalid = context
        .auth_mfa_use_case()
        .verify_totp_mfa(VerifyTotpMfaCommand {
            mfa_ticket: "bad-totp-ticket".to_string(),
            code: "000000".to_string(),
        })
        .await;
    assert_eq!(invalid, Err(AuthError::MfaCodeInvalid));
}

#[tokio::test]
async fn setup_and_disable_mfa_require_current_password_contract() {
    let context = AuthUseCaseTestContext::default();
    let mut user = verified_user("settings@example.com");
    user.mfa_totp_enabled = true;
    context.user_repository.insert_user(user.clone());
    let auth = AuthenticatedUserContext {
        user_id: user.id,
        mfa_satisfied: true,
        session_jti_hash: None,
    };

    let setup_totp = context
        .auth_mfa_use_case()
        .setup_totp(
            auth.clone(),
            SetupTotpCommand {
                current_password: None,
            },
        )
        .await;
    let setup_email = context
        .auth_mfa_use_case()
        .setup_email_mfa(
            auth.clone(),
            SetupEmailMfaCommand {
                current_password: None,
            },
        )
        .await;
    let verify_totp = context
        .auth_mfa_use_case()
        .verify_totp_setup(
            auth.clone(),
            VerifyTotpSetupCommand {
                setup_ticket: "setup".to_string(),
                code: "123456".to_string(),
                current_password: None,
            },
        )
        .await;
    let verify_email = context
        .auth_mfa_use_case()
        .verify_email_mfa_setup(
            auth.clone(),
            VerifyEmailMfaSetupCommand {
                code: "123456".to_string(),
                current_password: None,
            },
        )
        .await;
    let disable = context
        .auth_mfa_use_case()
        .disable_mfa(
            auth,
            DisableMfaCommand {
                current_password: None,
            },
        )
        .await;

    assert_eq!(setup_totp, Err(AuthError::CurrentPasswordRequired));
    assert_eq!(setup_email, Err(AuthError::CurrentPasswordRequired));
    assert_eq!(verify_totp, Err(AuthError::CurrentPasswordRequired));
    assert_eq!(verify_email, Err(AuthError::CurrentPasswordRequired));
    assert_eq!(disable, Err(AuthError::CurrentPasswordRequired));
}
