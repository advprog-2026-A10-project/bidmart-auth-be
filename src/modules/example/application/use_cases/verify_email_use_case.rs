use std::sync::Arc;

use crate::modules::example::application::dto::{VerifyEmailCommand, VerifyEmailResult};
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, UserRepository, VerificationTokenHasher,
};

pub struct VerifyEmailUseCase {
    user_repository: Arc<dyn UserRepository>,
    token_repository: Arc<dyn EmailVerificationTokenRepository>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    clock: Arc<dyn Clock>,
}

impl VerifyEmailUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn EmailVerificationTokenRepository>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            user_repository,
            token_repository,
            token_hasher,
            clock,
        }
    }

    pub async fn execute(
        &self,
        command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, AuthError> {
        let now = self.clock.now();
        let token_hash = self.token_hasher.hash(&command.token)?;
        let token = self
            .token_repository
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(AuthError::VerificationTokenInvalid)?;

        if token.is_consumed_or_invalidated() {
            return Err(AuthError::VerificationTokenAlreadyUsed);
        }

        if token.is_expired_at(now) {
            return Err(AuthError::VerificationTokenExpired);
        }

        let user = self
            .user_repository
            .find_by_id(token.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if user.is_email_verified() {
            return Err(AuthError::UserAlreadyVerified);
        }

        self.user_repository
            .mark_email_verified(user.id, now)
            .await?;
        self.token_repository.consume(token.id, now).await?;

        Ok(VerifyEmailResult {
            user_id: user.id,
            email_verified: true,
        })
    }
}
