use std::sync::Arc;

use uuid::Uuid;
use validator::ValidateEmail;

use crate::modules::example::application::dto::{
    ResendVerificationCommand, ResendVerificationResult,
};
use crate::modules::example::application::use_cases::policy::AuthPolicy;
use crate::modules::example::domain::entities::EmailVerificationToken;
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, UserRepository, VerificationEmailSender,
    VerificationTokenGenerator, VerificationTokenHasher,
};

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

        let user = self
            .user_repository
            .find_by_email(&normalized_email)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if user.is_email_verified() {
            return Err(AuthError::UserAlreadyVerified);
        }

        let now = self.clock.now();
        if let Some(existing_token) = self
            .token_repository
            .find_latest_active_by_user_id(user.id)
            .await?
        {
            if existing_token.created_at + self.policy.resend_cooldown > now {
                return Err(AuthError::VerificationCooldownActive);
            }

            self.token_repository
                .invalidate_active_tokens_for_user(user.id, now)
                .await?;
        }

        let raw_token = self.token_generator.generate()?;
        let token_hash = self.token_hasher.hash(&raw_token)?;
        let token = EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            created_at: now,
            expires_at: now + self.policy.verification_token_ttl,
            consumed_at: None,
            invalidated_at: None,
        };

        self.token_repository.save(token).await?;
        self.email_sender
            .send_verification_email(&user.email, &raw_token)
            .await?;

        Ok(ResendVerificationResult {
            user_id: user.id,
            email: user.email,
        })
    }
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}
