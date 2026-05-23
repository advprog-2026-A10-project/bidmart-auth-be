use std::sync::Arc;

use uuid::Uuid;

use crate::modules::auth::application::dto::{
    AuthenticatedUserContext, DisableMfaCommand, MfaSettingsDto,
    SetupEmailMfaCommand, SetupTotpCommand, SetupTotpResult, VerifyEmailMfaSetupCommand,
    VerifyTotpSetupCommand,
};
use crate::modules::auth::application::use_cases::helpers::require_settings_user;
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::{EmailMfaCode, EmailMfaCodePurpose, TotpSetup};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailMfaCodeRepository, MfaEmailSender, PasswordVerifier, TotpService,
    TotpSetupRepository, UserRepository, VerificationTokenGenerator, VerificationTokenHasher,
};

pub struct MfaSetupUseCase {
    user_repository: Arc<dyn UserRepository>,
    email_mfa_code_repository: Arc<dyn EmailMfaCodeRepository>,
    totp_setup_repository: Arc<dyn TotpSetupRepository>,
    password_verifier: Arc<dyn PasswordVerifier>,
    token_generator: Arc<dyn VerificationTokenGenerator>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    mfa_email_sender: Arc<dyn MfaEmailSender>,
    totp_service: Arc<dyn TotpService>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl MfaSetupUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        email_mfa_code_repository: Arc<dyn EmailMfaCodeRepository>,
        totp_setup_repository: Arc<dyn TotpSetupRepository>,
        password_verifier: Arc<dyn PasswordVerifier>,
        token_generator: Arc<dyn VerificationTokenGenerator>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        mfa_email_sender: Arc<dyn MfaEmailSender>,
        totp_service: Arc<dyn TotpService>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            user_repository,
            email_mfa_code_repository,
            totp_setup_repository,
            password_verifier,
            token_generator,
            token_hasher,
            mfa_email_sender,
            totp_service,
            clock,
            policy,
        }
    }

    pub async fn get_mfa_settings(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<MfaSettingsDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        let mfa_type = if user.mfa_totp_enabled {
            Some("totp".to_string())
        } else if user.mfa_email_enabled {
            Some("email".to_string())
        } else {
            None
        };
        Ok(MfaSettingsDto {
            mfa_enabled: user.mfa_email_enabled || user.mfa_totp_enabled,
            mfa_type,
        })
    }

    pub async fn setup_totp(
        &self,
        auth: AuthenticatedUserContext,
        command: SetupTotpCommand,
    ) -> Result<SetupTotpResult, AuthError> {
        let user = self
            .require_current_password(&auth, command.current_password.as_deref())
            .await?;
        let secret = self.totp_service.generate_secret()?;
        let raw_setup_ticket = self.token_generator.generate()?;
        let setup_ticket_hash = self.token_hasher.hash(&raw_setup_ticket)?;
        let now = self.clock.now();
        self.totp_setup_repository
            .save(TotpSetup {
                id: Uuid::new_v4(),
                user_id: user.id,
                setup_ticket_hash,
                secret: secret.clone(),
                created_at: now,
                expires_at: now + self.policy.totp_setup_ttl,
                consumed_at: None,
            })
            .await?;
        let otpauth_url = self.totp_service.otpauth_url(&user.email, &secret)?;
        Ok(SetupTotpResult {
            setup_ticket: raw_setup_ticket,
            otpauth_url: otpauth_url.clone(),
            qr_code_url: otpauth_url,
            secret,
        })
    }

    pub async fn verify_totp_setup(
        &self,
        auth: AuthenticatedUserContext,
        command: VerifyTotpSetupCommand,
    ) -> Result<(), AuthError> {
        let user = self
            .require_current_password(&auth, command.current_password.as_deref())
            .await?;
        let now = self.clock.now();
        let setup_hash = self.token_hasher.hash(&command.setup_ticket)?;
        let setup = self
            .totp_setup_repository
            .find_by_ticket_hash(&setup_hash)
            .await?
            .ok_or(AuthError::TotpSetupInvalid)?;
        if setup.user_id != user.id || setup.consumed_at.is_some() {
            return Err(AuthError::TotpSetupInvalid);
        }
        if setup.is_expired_at(now) {
            return Err(AuthError::TotpSetupInvalid);
        }
        if !self
            .totp_service
            .verify_code(&setup.secret, &command.code, now)?
        {
            return Err(AuthError::MfaCodeInvalid);
        }
        if !self.totp_setup_repository.consume(setup.id, now).await? {
            return Err(AuthError::TotpSetupInvalid);
        }
        self.user_repository
            .update_mfa_totp(user.id, true, Some(setup.secret), now)
            .await
    }

    pub async fn setup_email_mfa(
        &self,
        auth: AuthenticatedUserContext,
        command: SetupEmailMfaCommand,
    ) -> Result<(), AuthError> {
        let user = self
            .require_current_password(&auth, command.current_password.as_deref())
            .await?;
        let now = self.clock.now();
        if let Some(active_code) = self
            .email_mfa_code_repository
            .find_latest_active_by_user_id(user.id, EmailMfaCodePurpose::Setup)
            .await?
        {
            if active_code.created_at + self.policy.email_mfa_cooldown > now {
                return Err(AuthError::MfaCodeCooldownActive);
            }
        }
        self.email_mfa_code_repository
            .invalidate_active_codes_for_user(user.id, EmailMfaCodePurpose::Setup, now)
            .await?;
        let raw_code = mfa_email_code_from_seed(&self.token_generator.generate()?);
        let code_hash = self.token_hasher.hash(&raw_code)?;
        self.email_mfa_code_repository
            .save(EmailMfaCode::new(
                Uuid::new_v4(),
                user.id,
                code_hash,
                EmailMfaCodePurpose::Setup,
                now,
                now + self.policy.email_mfa_code_ttl,
            ))
            .await?;
        self.mfa_email_sender
            .send_mfa_code(&user.email, &raw_code)
            .await
    }

    pub async fn verify_email_mfa_setup(
        &self,
        auth: AuthenticatedUserContext,
        command: VerifyEmailMfaSetupCommand,
    ) -> Result<(), AuthError> {
        let user = self
            .require_current_password(&auth, command.current_password.as_deref())
            .await?;
        let now = self.clock.now();
        let code_hash = self.token_hasher.hash(&command.code)?;
        let code = self
            .email_mfa_code_repository
            .find_by_code_hash(&code_hash)
            .await?
            .ok_or(AuthError::MfaCodeInvalid)?;
        if code.user_id != user.id || code.purpose != EmailMfaCodePurpose::Setup {
            return Err(AuthError::MfaCodeInvalid);
        }
        if code.consumed_at.is_some() || code.invalidated_at.is_some() {
            return Err(AuthError::MfaCodeAlreadyUsed);
        }
        if code.is_expired_at(now) {
            return Err(AuthError::MfaCodeExpired);
        }
        if !self.email_mfa_code_repository.consume(code.id, now).await? {
            return Err(AuthError::MfaCodeAlreadyUsed);
        }
        self.user_repository
            .update_mfa_email_enabled(user.id, true, now)
            .await
    }

    pub async fn disable_mfa(
        &self,
        auth: AuthenticatedUserContext,
        command: DisableMfaCommand,
    ) -> Result<(), AuthError> {
        let user = self
            .require_current_password(&auth, command.current_password.as_deref())
            .await?;
        self.user_repository
            .disable_mfa(user.id, self.clock.now())
            .await
    }

    async fn require_current_password(
        &self,
        auth: &AuthenticatedUserContext,
        current_password: Option<&str>,
    ) -> Result<crate::modules::auth::domain::entities::User, AuthError> {
        let password = current_password
            .filter(|value| !value.trim().is_empty())
            .ok_or(AuthError::CurrentPasswordRequired)?;
        let user = require_settings_user(&self.user_repository, auth).await?;
        if !self
            .password_verifier
            .verify(password, &user.password_hash)?
        {
            return Err(AuthError::CurrentPasswordInvalid);
        }
        Ok(user)
    }
}

fn mfa_email_code_from_seed(seed: &str) -> String {
    let trimmed = seed.trim();
    if trimmed.len() == 6 && trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return trimmed.to_string();
    }
    let mut acc: u64 = 0;
    for byte in trimmed.as_bytes() {
        acc = acc.wrapping_mul(131).wrapping_add(u64::from(*byte));
    }
    format!("{:06}", acc % 1_000_000)
}
