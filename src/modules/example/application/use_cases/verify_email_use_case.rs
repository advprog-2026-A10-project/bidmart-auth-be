use std::sync::Arc;

use crate::modules::example::application::dto::{VerifyEmailCommand, VerifyEmailResult};
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, UserRepository, VerificationTokenHasher,
};

pub struct VerifyEmailUseCase {
    _user_repository: Arc<dyn UserRepository>,
    _token_repository: Arc<dyn EmailVerificationTokenRepository>,
    _token_hasher: Arc<dyn VerificationTokenHasher>,
    _clock: Arc<dyn Clock>,
}

impl VerifyEmailUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn EmailVerificationTokenRepository>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            _user_repository: user_repository,
            _token_repository: token_repository,
            _token_hasher: token_hasher,
            _clock: clock,
        }
    }

    pub async fn execute(
        &self,
        _command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, AuthError> {
        Err(AuthError::NotImplemented("VerifyEmailUseCase::execute"))
    }
}
