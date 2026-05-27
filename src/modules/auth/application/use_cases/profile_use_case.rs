use std::sync::Arc;

use crate::modules::auth::application::dto::{
    AuthenticatedUserContext, ChangePasswordCommand, MessageResponseDto,
    SettingsProfileResponseDto, SettingsProfileUserDto, UpdateProfileCommand,
    UpdateProfileResponseDto,
};
use crate::modules::auth::application::use_cases::helpers::require_settings_user;
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::User;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, PasswordHasher, PasswordVerifier, SessionRepository, UserRepository,
};

pub struct ProfileUseCase {
    user_repository: Arc<dyn UserRepository>,
    session_repository: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    password_verifier: Arc<dyn PasswordVerifier>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl ProfileUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        session_repository: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        password_verifier: Arc<dyn PasswordVerifier>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            user_repository,
            session_repository,
            password_hasher,
            password_verifier,
            clock,
            policy,
        }
    }

    pub async fn get_profile(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<SettingsProfileResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        Ok(SettingsProfileResponseDto {
            user: profile_dto(&user),
        })
    }

    pub async fn update_profile(
        &self,
        auth: AuthenticatedUserContext,
        command: UpdateProfileCommand,
    ) -> Result<UpdateProfileResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        let updated = self
            .user_repository
            .update_profile(
                user.id,
                &command.name,
                &command.address,
                &command.postal_code,
                self.clock.now(),
            )
            .await?;
        Ok(UpdateProfileResponseDto {
            message: "Profile updated.".to_string(),
            user: profile_dto(&updated),
        })
    }

    pub async fn change_password(
        &self,
        auth: AuthenticatedUserContext,
        command: ChangePasswordCommand,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        if !self
            .password_verifier
            .verify(&command.current_password, &user.password_hash)?
        {
            return Err(AuthError::CurrentPasswordInvalid);
        }
        if command.new_password.chars().count() < self.policy.min_password_length {
            return Err(AuthError::WeakPassword);
        }
        let password_hash = self.password_hasher.hash(&command.new_password)?;
        self.user_repository
            .update_password_hash(user.id, password_hash, self.clock.now())
            .await?;
        self.session_repository
            .revoke_all_other_sessions(user.id, auth.session_jti_hash.as_deref(), self.clock.now())
            .await?;
        Ok(MessageResponseDto {
            message: "Password changed.".to_string(),
        })
    }
}

fn profile_dto(user: &User) -> SettingsProfileUserDto {
    SettingsProfileUserDto {
        id: user.id,
        name: user.display_name(),
        email: user.email.clone(),
        address: user.address.clone(),
        postal_code: user.postal_code.clone(),
    }
}
