use std::sync::Arc;

use uuid::Uuid;
use validator::ValidateEmail;

use crate::modules::auth::application::dto::{
    AuthTokenResult, AuthenticatedLoginResult, AuthenticatedUserContext, ChangePasswordCommand,
    DisableMfaCommand, LoginCommand, LoginOutcome, MessageResponseDto, MfaSettingsDto,
    NotificationPreferencesDto, NotificationPreferencesResponseDto, PublicUserDto,
    SendEmailMfaCommand, SessionDto, SessionsResponseDto, SettingsProfileResponseDto,
    SettingsProfileUserDto, SetupEmailMfaCommand, SetupTotpCommand, SetupTotpResult,
    UpdateNotificationPreferencesCommand, UpdateProfileCommand, UpdateProfileResponseDto,
    VerifyEmailMfaCommand, VerifyEmailMfaSetupCommand, VerifyTotpMfaCommand,
    VerifyTotpSetupCommand,
};
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::{
    AuthSession, EmailMfaCode, EmailMfaCodePurpose, MfaTicket, NotificationPreferences, TotpSetup,
    User,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailMfaCodeRepository, JwtService, MfaEmailSender, MfaTicketRepository,
    NotificationPreferencesRepository, PasswordHasher, PasswordVerifier, SessionRepository,
    TotpService, TotpSetupRepository, UserRepository, VerificationTokenGenerator,
    VerificationTokenHasher,
};

pub struct AuthMfaUseCase {
    user_repository: Arc<dyn UserRepository>,
    mfa_ticket_repository: Arc<dyn MfaTicketRepository>,
    email_mfa_code_repository: Arc<dyn EmailMfaCodeRepository>,
    session_repository: Arc<dyn SessionRepository>,
    notification_preferences_repository: Arc<dyn NotificationPreferencesRepository>,
    totp_setup_repository: Arc<dyn TotpSetupRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    password_verifier: Arc<dyn PasswordVerifier>,
    token_generator: Arc<dyn VerificationTokenGenerator>,
    token_hasher: Arc<dyn VerificationTokenHasher>,
    mfa_email_sender: Arc<dyn MfaEmailSender>,
    jwt_service: Arc<dyn JwtService>,
    totp_service: Arc<dyn TotpService>,
    clock: Arc<dyn Clock>,
    policy: AuthPolicy,
}

impl AuthMfaUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        mfa_ticket_repository: Arc<dyn MfaTicketRepository>,
        email_mfa_code_repository: Arc<dyn EmailMfaCodeRepository>,
        session_repository: Arc<dyn SessionRepository>,
        notification_preferences_repository: Arc<dyn NotificationPreferencesRepository>,
        totp_setup_repository: Arc<dyn TotpSetupRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        password_verifier: Arc<dyn PasswordVerifier>,
        token_generator: Arc<dyn VerificationTokenGenerator>,
        token_hasher: Arc<dyn VerificationTokenHasher>,
        mfa_email_sender: Arc<dyn MfaEmailSender>,
        jwt_service: Arc<dyn JwtService>,
        totp_service: Arc<dyn TotpService>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            user_repository,
            mfa_ticket_repository,
            email_mfa_code_repository,
            session_repository,
            notification_preferences_repository,
            totp_setup_repository,
            password_hasher,
            password_verifier,
            token_generator,
            token_hasher,
            mfa_email_sender,
            jwt_service,
            totp_service,
            clock,
            policy,
        }
    }

    pub async fn login(&self, command: LoginCommand) -> Result<LoginOutcome, AuthError> {
        let normalized_email = normalize_email(&command.email);
        if !normalized_email.validate_email() {
            return Err(AuthError::InvalidCredentials);
        }

        let user = self
            .user_repository
            .find_by_email(&normalized_email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        let password_matches = self
            .password_verifier
            .verify(&command.password, &user.password_hash)?;
        if !password_matches {
            return Err(AuthError::InvalidCredentials);
        }

        require_login_allowed(&user)?;

        if user.has_mfa_enabled() {
            let raw_ticket = self.token_generator.generate()?;
            let ticket_hash = self.token_hasher.hash(&raw_ticket)?;
            let now = self.clock.now();
            self.mfa_ticket_repository
                .save(MfaTicket::new(
                    Uuid::new_v4(),
                    user.id,
                    ticket_hash,
                    now,
                    now + self.policy.mfa_ticket_ttl,
                ))
                .await?;

            return Ok(LoginOutcome::MfaRequired {
                mfa_ticket: raw_ticket,
                mfa_type: primary_mfa_type(&user),
            });
        }

        let access_token = self.issue_access_token(&user, true).await?;
        Ok(LoginOutcome::Authenticated(AuthenticatedLoginResult {
            user_id: access_token.user_id,
            name: access_token.name,
            email: access_token.email,
            email_verified: access_token.email_verified,
            access_token: access_token.access_token,
        }))
    }

    pub async fn send_email_mfa(&self, command: SendEmailMfaCommand) -> Result<(), AuthError> {
        let ticket = self.valid_mfa_ticket(&command.mfa_ticket).await?;
        let user = self.require_user_for_mfa_ticket(&ticket).await?;
        if !user.mfa_email_enabled {
            return Err(AuthError::MfaTicketInvalid);
        }

        let now = self.clock.now();
        if let Some(active_code) = self
            .email_mfa_code_repository
            .find_latest_active_by_user_id(user.id, EmailMfaCodePurpose::Login)
            .await?
        {
            if active_code.created_at + self.policy.email_mfa_cooldown > now {
                return Err(AuthError::MfaCodeCooldownActive);
            }
        }

        self.email_mfa_code_repository
            .invalidate_active_codes_for_user(user.id, EmailMfaCodePurpose::Login, now)
            .await?;

        let raw_code = self.token_generator.generate()?;
        let code_hash = self.token_hasher.hash(&raw_code)?;
        self.email_mfa_code_repository
            .save(EmailMfaCode::new(
                Uuid::new_v4(),
                user.id,
                code_hash,
                EmailMfaCodePurpose::Login,
                now,
                now + self.policy.email_mfa_code_ttl,
            ))
            .await?;
        self.mfa_email_sender
            .send_mfa_code(&user.email, &raw_code)
            .await?;

        Ok(())
    }

    pub async fn verify_email_mfa(
        &self,
        command: VerifyEmailMfaCommand,
    ) -> Result<AuthTokenResult, AuthError> {
        let ticket = self.valid_mfa_ticket(&command.mfa_ticket).await?;
        let user = self.require_user_for_mfa_ticket(&ticket).await?;
        if !user.mfa_email_enabled {
            return Err(AuthError::MfaTicketInvalid);
        }

        let now = self.clock.now();
        let code_hash = self.token_hasher.hash(&command.code)?;
        let code = self
            .email_mfa_code_repository
            .find_by_code_hash(&code_hash)
            .await?
            .ok_or(AuthError::MfaCodeInvalid)?;

        if code.user_id != user.id || code.purpose != EmailMfaCodePurpose::Login {
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
        if !self.mfa_ticket_repository.consume(ticket.id, now).await? {
            return Err(AuthError::MfaTicketInvalid);
        }

        self.issue_access_token(&user, true).await
    }

    pub async fn verify_totp_mfa(
        &self,
        command: VerifyTotpMfaCommand,
    ) -> Result<AuthTokenResult, AuthError> {
        let ticket = self.valid_mfa_ticket(&command.mfa_ticket).await?;
        let user = self.require_user_for_mfa_ticket(&ticket).await?;
        let secret = user
            .mfa_totp_secret
            .as_deref()
            .filter(|_| user.mfa_totp_enabled)
            .ok_or(AuthError::MfaTicketInvalid)?;

        if !self
            .totp_service
            .verify_code(secret, &command.code, self.clock.now())?
        {
            return Err(AuthError::MfaCodeInvalid);
        }

        if !self
            .mfa_ticket_repository
            .consume(ticket.id, self.clock.now())
            .await?
        {
            return Err(AuthError::MfaTicketInvalid);
        }

        self.issue_access_token(&user, true).await
    }

    pub async fn get_mfa_settings(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<MfaSettingsDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
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

    pub async fn get_profile(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<SettingsProfileResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        Ok(SettingsProfileResponseDto {
            user: profile_dto(&user),
        })
    }

    pub async fn current_user(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<PublicUserDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        Ok(public_user_dto(&user))
    }

    pub async fn update_profile(
        &self,
        auth: AuthenticatedUserContext,
        command: UpdateProfileCommand,
    ) -> Result<UpdateProfileResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
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
        let user = self.require_settings_user(&auth).await?;
        if !self
            .password_verifier
            .verify(&command.current_password, &user.password_hash)?
        {
            return Err(AuthError::CurrentPasswordInvalid);
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

    pub async fn get_sessions(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<SessionsResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        let current_jti_hash = auth.session_jti_hash.as_deref();
        let sessions = self
            .session_repository
            .list_active_by_user_id(user.id, self.clock.now())
            .await?
            .into_iter()
            .map(|session| SessionDto {
                id: session.id,
                device: session.device,
                browser: session.browser,
                os: session.os,
                ip: session.ip,
                location: session.location,
                last_active: session.last_active_at.to_rfc3339(),
                is_current: current_jti_hash == Some(session.jti_hash.as_str()),
            })
            .collect();
        Ok(SessionsResponseDto { sessions })
    }

    pub async fn revoke_session(
        &self,
        auth: AuthenticatedUserContext,
        session_id: Uuid,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        let revoked = self
            .session_repository
            .revoke_session(
                user.id,
                session_id,
                auth.session_jti_hash.as_deref(),
                self.clock.now(),
            )
            .await?;
        if !revoked {
            return Err(AuthError::SessionNotFound);
        }
        Ok(MessageResponseDto {
            message: "Session revoked.".to_string(),
        })
    }

    pub async fn revoke_all_sessions(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        self.session_repository
            .revoke_all_other_sessions(user.id, auth.session_jti_hash.as_deref(), self.clock.now())
            .await?;
        Ok(MessageResponseDto {
            message: "Sessions revoked.".to_string(),
        })
    }

    pub async fn logout(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        let jti_hash = auth
            .session_jti_hash
            .as_deref()
            .ok_or(AuthError::SessionInvalid)?;
        let revoked = self
            .session_repository
            .revoke_current_session(user.id, jti_hash, self.clock.now())
            .await?;
        if !revoked {
            return Err(AuthError::SessionInvalid);
        }
        Ok(MessageResponseDto {
            message: "Logged out.".to_string(),
        })
    }

    pub async fn get_notification_preferences(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<NotificationPreferencesResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        let preferences = self
            .notification_preferences_repository
            .get_by_user_id(user.id)
            .await?;
        Ok(NotificationPreferencesResponseDto {
            preferences: preferences.into(),
        })
    }

    pub async fn update_notification_preferences(
        &self,
        auth: AuthenticatedUserContext,
        command: UpdateNotificationPreferencesCommand,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = self.require_settings_user(&auth).await?;
        self.notification_preferences_repository
            .upsert(user.id, command.preferences.into())
            .await?;
        Ok(MessageResponseDto {
            message: "Notification preferences updated.".to_string(),
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
        let raw_code = self.token_generator.generate()?;
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

    async fn valid_mfa_ticket(&self, raw_ticket: &str) -> Result<MfaTicket, AuthError> {
        let ticket_hash = self.token_hasher.hash(raw_ticket)?;
        let ticket = self
            .mfa_ticket_repository
            .find_by_ticket_hash(&ticket_hash)
            .await?
            .ok_or(AuthError::MfaTicketInvalid)?;

        if ticket.consumed_at.is_some() {
            return Err(AuthError::MfaTicketInvalid);
        }
        if ticket.is_expired_at(self.clock.now()) {
            return Err(AuthError::MfaTicketExpired);
        }
        Ok(ticket)
    }

    async fn require_user_for_mfa_ticket(&self, ticket: &MfaTicket) -> Result<User, AuthError> {
        let user = self
            .user_repository
            .find_by_id(ticket.user_id)
            .await?
            .ok_or(AuthError::MfaTicketInvalid)?;
        require_login_allowed(&user)?;
        Ok(user)
    }

    async fn require_settings_user(
        &self,
        auth: &AuthenticatedUserContext,
    ) -> Result<User, AuthError> {
        let user = self
            .user_repository
            .find_by_id(auth.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        require_login_allowed(&user)?;
        if user.has_mfa_enabled() && !auth.mfa_satisfied {
            return Err(AuthError::Forbidden);
        }
        Ok(user)
    }

    async fn require_current_password(
        &self,
        auth: &AuthenticatedUserContext,
        current_password: Option<&str>,
    ) -> Result<User, AuthError> {
        let password = current_password
            .filter(|value| !value.trim().is_empty())
            .ok_or(AuthError::CurrentPasswordRequired)?;
        let user = self.require_settings_user(auth).await?;
        if !self
            .password_verifier
            .verify(password, &user.password_hash)?
        {
            return Err(AuthError::CurrentPasswordInvalid);
        }
        Ok(user)
    }

    async fn issue_access_token(
        &self,
        user: &User,
        mfa_satisfied: bool,
    ) -> Result<AuthTokenResult, AuthError> {
        let now = self.clock.now();
        let issued = self
            .jwt_service
            .issue_access_token(user.id, mfa_satisfied, now)?;
        let jti_hash = self.jwt_service.jti_hash(&issued.jti)?;
        let session_expires_at =
            std::cmp::min(issued.expires_at, now + self.policy.access_token_ttl);
        self.session_repository
            .save(AuthSession {
                id: Uuid::new_v4(),
                user_id: user.id,
                jti_hash,
                mfa_satisfied,
                device: "Unknown device".to_string(),
                browser: "Unknown browser".to_string(),
                os: "Unknown OS".to_string(),
                ip: "Unknown IP".to_string(),
                location: "Unknown location".to_string(),
                created_at: now,
                last_active_at: now,
                expires_at: session_expires_at,
            })
            .await?;
        Ok(AuthTokenResult {
            user_id: user.id,
            name: user.display_name(),
            email: user.email.clone(),
            email_verified: user.is_email_verified(),
            access_token: issued.token,
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

fn public_user_dto(user: &User) -> PublicUserDto {
    PublicUserDto {
        id: user.id,
        name: user.display_name(),
        email: user.email.clone(),
        email_verified: user.is_email_verified(),
    }
}

impl From<NotificationPreferences> for NotificationPreferencesDto {
    fn from(preferences: NotificationPreferences) -> Self {
        Self {
            email_notifications: preferences.email_notifications,
            push_notifications: preferences.push_notifications,
            marketing_emails: preferences.marketing_emails,
            security_alerts: preferences.security_alerts,
        }
    }
}

impl From<NotificationPreferencesDto> for NotificationPreferences {
    fn from(preferences: NotificationPreferencesDto) -> Self {
        Self {
            email_notifications: preferences.email_notifications,
            push_notifications: preferences.push_notifications,
            marketing_emails: preferences.marketing_emails,
            security_alerts: preferences.security_alerts,
        }
    }
}

fn require_login_allowed(user: &User) -> Result<(), AuthError> {
    if !user.is_active() {
        if !user.is_email_verified() {
            return Err(AuthError::EmailNotVerified);
        }
        return Err(AuthError::UserDisabled);
    }
    if !user.is_email_verified() {
        return Err(AuthError::EmailNotVerified);
    }
    Ok(())
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn primary_mfa_type(user: &User) -> String {
    if user.mfa_totp_enabled {
        "totp".to_string()
    } else {
        "email".to_string()
    }
}
