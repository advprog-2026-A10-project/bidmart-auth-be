use std::sync::Arc;

use crate::modules::auth::application::dto::{
    VerifyEmailCommand, VerifyEmailResult, VERIFY_EMAIL_SUCCESS_MESSAGE,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
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
        let raw_token = command.token.trim();
        if raw_token.is_empty() {
            return Err(AuthError::VerificationTokenInvalid);
        }

        let now = self.clock.now();
        let token_hash = self.token_hasher.hash(raw_token)?;
        let token = self
            .token_repository
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(AuthError::VerificationTokenInvalid)?;

        if token.consumed_at.is_some() || token.invalidated_at.is_some() {
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

        let consumed = self.token_repository.consume(token.id, now).await?;
        if !consumed {
            return Err(AuthError::VerificationTokenAlreadyUsed);
        }

        self.user_repository
            .mark_email_verified(user.id, now)
            .await?;

        Ok(VerifyEmailResult {
            user_id: user.id,
            message: VERIFY_EMAIL_SUCCESS_MESSAGE.to_string(),
        })
    }
}
