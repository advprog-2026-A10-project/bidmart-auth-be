use std::sync::Arc;

use uuid::Uuid;
use validator::ValidateEmail;

use crate::modules::example::application::dto::{RegisterUserCommand, RegisterUserResult};
use crate::modules::example::application::use_cases::policy::AuthPolicy;
use crate::modules::example::domain::entities::{EmailVerificationToken, User};
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, PasswordHasher, UserRepository,
    VerificationEmailSender, VerificationTokenGenerator, VerificationTokenHasher,
};

pub struct RegisterUserUseCase {
    user_repository: Arc<dyn UserRepository>,
    token_repository: Arc<dyn EmailVerificationTokenRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_generator: Arc<dyn VerificationTokenGenerator>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    email_sender: Arc<dyn VerificationEmailSender>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
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
            user_repository,
            token_repository,
            password_hasher,
            token_generator,
            token_hasher,
            email_sender,
            clock,
            policy,
        }
    }

    pub async fn execute(
        &self,
        command: RegisterUserCommand,
    ) -> Result<RegisterUserResult, AuthError> {
        let normalized_email = normalize_email(&command.email);
        if !normalized_email.validate_email() {
            return Err(AuthError::InvalidEmail);
        }

        if command.password.chars().count() < self.policy.min_password_length {
            return Err(AuthError::WeakPassword);
        }

        if self
            .user_repository
            .find_by_email(&normalized_email)
            .await?
            .is_some()
        {
            return Err(AuthError::EmailAlreadyExists);
        }

        let now = self.clock.now();
        let password_hash = self.password_hasher.hash(&command.password)?;
        let user = User::new(Uuid::new_v4(), normalized_email, password_hash, now);
        let created_user = self.user_repository.create(user).await?;

        let raw_token = self.token_generator.generate()?;
        let token_hash = self.token_hasher.hash(&raw_token)?;
        let token = EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: created_user.id,
            token_hash,
            created_at: now,
            expires_at: now + self.policy.verification_token_ttl,
            consumed_at: None,
            invalidated_at: None,
        };

        self.token_repository.save(token).await?;
        self.email_sender
            .send_verification_email(&created_user.email, &raw_token)
            .await?;

        let email_verified = created_user.is_email_verified();
        Ok(RegisterUserResult {
            user_id: created_user.id,
            email: created_user.email,
            email_verified,
        })
    }
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}
