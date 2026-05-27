use std::sync::Arc;

use crate::modules::auth::application::dto::{RegisterUserCommand, RegisterUserResult};
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::{normalize_name, EmailVerificationToken, User};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailVerificationTokenRepository, PasswordHasher, UserRepository,
    VerificationEmailSender, VerificationTokenGenerator, VerificationTokenHasher,
};
use uuid::Uuid;
use validator::ValidateEmail;

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
        let normalized_name = normalize_name(&command.name).ok_or(AuthError::InvalidName)?;
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
        let raw_token = self.token_generator.generate()?;
        let token_hash = self.token_hasher.hash(&raw_token)?;

        let user = User::new(
            Uuid::new_v4(),
            &normalized_name,
            normalized_email,
            password_hash,
            now,
        );
        let created_user = self.user_repository.create(user).await?;
        let token = EmailVerificationToken::new(
            Uuid::new_v4(),
            created_user.id,
            token_hash,
            now,
            now + self.policy.verification_token_ttl,
        );

        self.token_repository.save(token).await?;
        self.email_sender
            .send_verification_email(&created_user.email, &raw_token)
            .await?;

        Ok(RegisterUserResult {
            user_id: created_user.id,
            name: created_user.display_name(),
            email: created_user.email.clone(),
            email_verified: created_user.is_email_verified(),
        })
    }
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}
