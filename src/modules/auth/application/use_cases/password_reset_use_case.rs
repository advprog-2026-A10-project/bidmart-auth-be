use std::sync::Arc;

use uuid::Uuid;
use validator::ValidateEmail;

use crate::modules::auth::application::dto::{
    ForgotPasswordCommand, ForgotPasswordResult, ResetPasswordCommand, ResetPasswordResult,
    FORGOT_PASSWORD_MESSAGE, RESET_PASSWORD_SUCCESS_MESSAGE,
};
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::PasswordResetToken;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, PasswordHasher, PasswordResetCompletionRepository, PasswordResetEmailSender,
    PasswordResetTokenRepository, UserRepository, VerificationTokenGenerator,
    VerificationTokenHasher,
};

pub struct ForgotPasswordUseCase {
    user_repository: Arc<dyn UserRepository>,
    token_repository: Arc<dyn PasswordResetTokenRepository>,
    token_generator: Arc<dyn VerificationTokenGenerator>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    email_sender: Arc<dyn PasswordResetEmailSender>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl ForgotPasswordUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn PasswordResetTokenRepository>,
        token_generator: Arc<dyn VerificationTokenGenerator>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        email_sender: Arc<dyn PasswordResetEmailSender>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            user_repository,
            token_repository,
            token_generator,
            token_hasher,
            email_sender,
            clock,
            policy,
        }
    }

    pub async fn execute(
        &self,
        command: ForgotPasswordCommand,
    ) -> Result<ForgotPasswordResult, AuthError> {
        let normalized_email = normalize_email(&command.email);
        if !normalized_email.validate_email() {
            return Err(AuthError::InvalidEmail);
        }

        let user = match self
            .user_repository
            .find_by_email(&normalized_email)
            .await?
        {
            Some(user) => user,
            None => {
                tracing::debug!(
                    target: "auth.forgot_password",
                    email = %normalized_email,
                    "No user found for forgot-password request"
                );
                return Ok(forgot_success_result());
            }
        };

        if !user.is_active() || !user.is_email_verified() {
            tracing::info!(
                target: "auth.forgot_password",
                user_id = %user.id,
                email = %normalized_email,
                is_active = user.is_active(),
                is_email_verified = user.is_email_verified(),
                "Skipping forgot-password email because user is inactive or unverified"
            );
            return Ok(forgot_success_result());
        }

        let now = self.clock.now();
        if let Some(active_token) = self
            .token_repository
            .find_latest_active_by_user_id(user.id)
            .await?
        {
            if !active_token.is_expired_at(now)
                && active_token.created_at + self.policy.password_reset_cooldown > now
            {
                tracing::info!(
                    target: "auth.forgot_password",
                    user_id = %user.id,
                    email = %normalized_email,
                    "Skipping forgot-password email because cooldown is still active"
                );
                return Ok(forgot_success_result());
            }
        }

        self.token_repository
            .invalidate_active_tokens_for_user(user.id, now)
            .await?;

        let raw_token = self.token_generator.generate()?;
        let token_hash = self.token_hasher.hash(&raw_token)?;
        self.token_repository
            .save(PasswordResetToken::new(
                Uuid::new_v4(),
                user.id,
                token_hash,
                now,
                now + self.policy.password_reset_token_ttl,
            ))
            .await?;
        if let Err(error) = self
            .email_sender
            .send_password_reset_email(&user.email, &raw_token)
            .await
        {
            tracing::error!(
                target: "auth.forgot_password",
                user_id = %user.id,
                email = %normalized_email,
                ?error,
                "Failed to dispatch forgot-password email; returning generic success"
            );
            return Ok(forgot_success_result());
        }
        tracing::info!(
            target: "auth.forgot_password",
            user_id = %user.id,
            email = %normalized_email,
            "Forgot-password reset email dispatch requested"
        );

        Ok(forgot_success_result())
    }
}

pub struct ResetPasswordUseCase {
    user_repository: Arc<dyn UserRepository>,
    token_repository: Arc<dyn PasswordResetTokenRepository>,
    completion_repository: Arc<dyn PasswordResetCompletionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl ResetPasswordUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn PasswordResetTokenRepository>,
        completion_repository: Arc<dyn PasswordResetCompletionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            user_repository,
            token_repository,
            completion_repository,
            password_hasher,
            token_hasher,
            clock,
            policy,
        }
    }

    pub async fn execute(
        &self,
        command: ResetPasswordCommand,
    ) -> Result<ResetPasswordResult, AuthError> {
        let raw_token = command.token.trim();
        if raw_token.is_empty() {
            return Err(AuthError::PasswordResetTokenInvalid);
        }

        if command.password.chars().count() < self.policy.min_password_length {
            return Err(AuthError::WeakPassword);
        }

        let now = self.clock.now();
        let token_hash = self.token_hasher.hash(raw_token)?;
        let token = self
            .token_repository
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(AuthError::PasswordResetTokenInvalid)?;

        if token.invalidated_at.is_some() {
            return Err(AuthError::PasswordResetTokenInvalid);
        }
        if token.consumed_at.is_some() {
            return Err(AuthError::PasswordResetTokenAlreadyUsed);
        }
        if token.is_expired_at(now) {
            return Err(AuthError::PasswordResetTokenExpired);
        }

        let user = self
            .user_repository
            .find_by_id(token.user_id)
            .await?
            .ok_or(AuthError::PasswordResetTokenInvalid)?;
        if !user.is_active() || !user.is_email_verified() {
            return Err(AuthError::PasswordResetTokenInvalid);
        }

        let password_hash = self.password_hasher.hash(&command.password)?;
        if !self
            .completion_repository
            .complete_password_reset(token.id, user.id, password_hash, now)
            .await?
        {
            return Err(AuthError::PasswordResetTokenAlreadyUsed);
        }

        Ok(ResetPasswordResult {
            message: RESET_PASSWORD_SUCCESS_MESSAGE.to_string(),
        })
    }
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn forgot_success_result() -> ForgotPasswordResult {
    ForgotPasswordResult {
        message: FORGOT_PASSWORD_MESSAGE.to_string(),
    }
}
