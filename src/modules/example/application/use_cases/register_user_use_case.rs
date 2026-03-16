use std::sync::Arc;

use crate::modules::example::application::dto::{RegisterUserCommand, RegisterUserResult};
use crate::modules::example::application::use_cases::policy::AuthPolicy;
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, PasswordHasher, UserRepository,
    VerificationEmailSender, VerificationTokenGenerator, VerificationTokenHasher,
};

pub struct RegisterUserUseCase {
    _user_repository: Arc<dyn UserRepository>,
    _token_repository: Arc<dyn EmailVerificationTokenRepository>,
    _password_hasher: Arc<dyn PasswordHasher>,
    _token_generator: Arc<dyn VerificationTokenGenerator>,
    _token_hasher: Arc<dyn VerificationTokenHasher>,
    _email_sender: Arc<dyn VerificationEmailSender>,
    _clock: Arc<dyn Clock>,
    _policy: AuthPolicy,
}

impl RegisterUserUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        token_repository: Arc<dyn EmailVerificationTokenRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_generator: Arc<dyn VerificationTokenGenerator>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        email_sender: Arc<dyn VerificationEmailSender>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            _user_repository: user_repository,
            _token_repository: token_repository,
            _password_hasher: password_hasher,
            _token_generator: token_generator,
            _token_hasher: token_hasher,
            _email_sender: email_sender,
            _clock: clock,
            _policy: policy,
        }
    }

    pub async fn execute(
        &self,
        _command: RegisterUserCommand,
    ) -> Result<RegisterUserResult, AuthError> {
        Err(AuthError::NotImplemented("RegisterUserUseCase::execute"))
    }
}
