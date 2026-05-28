use std::sync::Arc;

use crate::modules::auth::application::dto::{
    ResendVerificationCommand, ResendVerificationResult, RESEND_VERIFICATION_MESSAGE,
};
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::EmailVerificationToken;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailVerificationTokenRepository, UserRepository, VerificationEmailSender,
    VerificationTokenGenerator, VerificationTokenHasher,
};
use uuid::Uuid;
use validator::ValidateEmail;

pub struct ResendVerificationUseCase {
    user_repository: Arc<dyn UserRepository>,
    token_repository: Arc<dyn EmailVerificationTokenRepository>,
    token_generator: Arc<dyn VerificationTokenGenerator>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    email_sender: Arc<dyn VerificationEmailSender>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl ResendVerificationUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn EmailVerificationTokenRepository>,
        token_generator: Arc<dyn VerificationTokenGenerator>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        email_sender: Arc<dyn VerificationEmailSender>,
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
        command: ResendVerificationCommand,
    ) -> Result<ResendVerificationResult, AuthError> {
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
            None => return Ok(success_result()),
        };

        if user.is_email_verified() {
            return Ok(success_result());
        }

        let now = self.clock.now();
        if let Some(active_token) = self
            .token_repository
            .find_latest_active_by_user_id(user.id)
            .await?
        {
            let next_allowed = active_token.created_at + self.policy.resend_cooldown;
            if next_allowed > now {
                return Err(AuthError::VerificationCooldownActive);
            }
        }

        self.token_repository
            .invalidate_active_tokens_for_user(user.id, now)
            .await?;

        let raw_token = self.token_generator.generate()?;
        let token_hash = self.token_hasher.hash(&raw_token)?;
        let token = EmailVerificationToken::new(
            Uuid::new_v4(),
            user.id,
            token_hash,
            now,
            now + self.policy.verification_token_ttl,
        );

        self.token_repository.save(token).await?;
        if let Err(error) = self
            .email_sender
            .send_verification_email(&user.email, &raw_token)
            .await
        {
            tracing::error!(
                target: "auth.resend_verification",
                user_id = %user.id,
                email = %user.email,
                ?error,
                "Failed to dispatch verification email; returning generic success"
            );
            return Ok(success_result());
        }

        Ok(success_result())
    }
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn success_result() -> ResendVerificationResult {
    ResendVerificationResult {
        message: RESEND_VERIFICATION_MESSAGE.to_string(),
    }
}
