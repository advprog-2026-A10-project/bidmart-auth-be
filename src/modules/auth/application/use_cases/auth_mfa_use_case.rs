use std::sync::Arc;

use uuid::Uuid;
use validator::ValidateEmail;

use crate::modules::auth::application::dto::{
    AuthTokenResult, AuthenticatedLoginResult, LoginCommand, LoginOutcome,
    SendEmailMfaCommand, SessionContext, VerifyEmailMfaCommand, VerifyTotpMfaCommand,
};
use crate::modules::auth::application::use_cases::helpers::require_login_allowed;
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::domain::entities::{
    AuthSession, EmailMfaCode, EmailMfaCodePurpose, MfaTicket, User,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailMfaCodeRepository, JwtService, MfaEmailSender, MfaTicketRepository,
    PasswordVerifier, SessionRepository, TotpService, UserRepository, VerificationTokenGenerator,
    VerificationTokenHasher,
};

pub struct AuthMfaUseCase {
    user_repository: Arc<dyn UserRepository>,
    mfa_ticket_repository: Arc<dyn MfaTicketRepository>,
    email_mfa_code_repository: Arc<dyn EmailMfaCodeRepository>,
    session_repository: Arc<dyn SessionRepository>,
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

    pub async fn login(
        &self,
        command: LoginCommand,
        session: SessionContext,
    ) -> Result<LoginOutcome, AuthError> {
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

        let access_token = self.issue_access_token(&user, true, session).await?;
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

        let raw_code = mfa_email_code_from_seed(&self.token_generator.generate()?);
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
        session: SessionContext,
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

        self.issue_access_token(&user, true, session).await
    }

    pub async fn verify_totp_mfa(
        &self,
        command: VerifyTotpMfaCommand,
        session: SessionContext,
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

        self.issue_access_token(&user, true, session).await
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

    async fn issue_access_token(
        &self,
        user: &User,
        mfa_satisfied: bool,
        session: SessionContext,
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
                device: session.device,
                browser: session.browser,
                os: session.os,
                ip: session.ip,
                location: session.location,
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
