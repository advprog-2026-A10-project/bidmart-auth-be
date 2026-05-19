use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::modules::auth::application::dto::{AuthenticatedUserContext, IssuedAccessToken};
use crate::modules::auth::domain::entities::{
    AuthSession, EmailMfaCode, EmailMfaCodePurpose, EmailVerificationToken, MfaTicket,
    NotificationPreferences, PasswordResetToken, TotpSetup, User,
};
use crate::modules::auth::domain::errors::AuthError;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, normalized_email: &str) -> Result<Option<User>, AuthError>;
    async fn create(&self, user: User) -> Result<User, AuthError>;
    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError>;
    async fn mark_email_verified(
        &self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn update_mfa_email_enabled(
        &self,
        user_id: Uuid,
        enabled: bool,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn update_mfa_totp(
        &self,
        user_id: Uuid,
        enabled: bool,
        secret: Option<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn disable_mfa(&self, user_id: Uuid, updated_at: DateTime<Utc>) -> Result<(), AuthError>;
    async fn update_profile(
        &self,
        user_id: Uuid,
        name: &str,
        address: &str,
        postal_code: &str,
        updated_at: DateTime<Utc>,
    ) -> Result<User, AuthError>;
    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait EmailVerificationTokenRepository: Send + Sync {
    async fn save(&self, token: EmailVerificationToken) -> Result<(), AuthError>;
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;
    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;
    async fn consume(&self, token_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError>;
    async fn invalidate_active_tokens_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, raw_password: &str) -> Result<String, AuthError>;
}

pub trait PasswordVerifier: Send + Sync {
    fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError>;
}

pub trait VerificationTokenGenerator: Send + Sync {
    fn generate(&self) -> Result<String, AuthError>;
}

pub trait VerificationTokenHasher: Send + Sync {
    fn hash(&self, raw_token: &str) -> Result<String, AuthError>;
}

#[async_trait]
pub trait VerificationEmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait MfaEmailSender: Send + Sync {
    async fn send_mfa_code(&self, to_email: &str, raw_code: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetEmailSender: Send + Sync {
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    async fn save(&self, token: PasswordResetToken) -> Result<(), AuthError>;
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PasswordResetToken>, AuthError>;
    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PasswordResetToken>, AuthError>;
    async fn invalidate_active_tokens_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetCompletionRepository: Send + Sync {
    async fn complete_password_reset(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        password_hash: String,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait MfaTicketRepository: Send + Sync {
    async fn save(&self, ticket: MfaTicket) -> Result<(), AuthError>;
    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<MfaTicket>, AuthError>;
    async fn consume(&self, ticket_id: Uuid, consumed_at: DateTime<Utc>)
        -> Result<bool, AuthError>;
}

#[async_trait]
pub trait EmailMfaCodeRepository: Send + Sync {
    async fn save(&self, code: EmailMfaCode) -> Result<(), AuthError>;
    async fn find_by_code_hash(&self, code_hash: &str) -> Result<Option<EmailMfaCode>, AuthError>;
    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
        purpose: EmailMfaCodePurpose,
    ) -> Result<Option<EmailMfaCode>, AuthError>;
    async fn consume(&self, code_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError>;
    async fn invalidate_active_codes_for_user(
        &self,
        user_id: Uuid,
        purpose: EmailMfaCodePurpose,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError>;
    async fn find_active_by_jti_hash(
        &self,
        jti_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError>;
    async fn list_active_by_user_id(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<AuthSession>, AuthError>;
    async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        current_jti_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError>;
    async fn revoke_current_session(
        &self,
        user_id: Uuid,
        current_jti_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError>;
    async fn revoke_all_other_sessions(
        &self,
        user_id: Uuid,
        current_jti_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait NotificationPreferencesRepository: Send + Sync {
    async fn get_by_user_id(&self, user_id: Uuid) -> Result<NotificationPreferences, AuthError>;
    async fn upsert(
        &self,
        user_id: Uuid,
        preferences: NotificationPreferences,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait TotpSetupRepository: Send + Sync {
    async fn save(&self, setup: TotpSetup) -> Result<(), AuthError>;
    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<TotpSetup>, AuthError>;
    async fn consume(&self, setup_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError>;
}

pub trait JwtService: Send + Sync {
    fn issue_access_token(
        &self,
        user_id: Uuid,
        mfa_satisfied: bool,
        now: DateTime<Utc>,
    ) -> Result<IssuedAccessToken, AuthError>;

    fn verify_access_token(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedUserContext, AuthError>;

    fn jti_hash(&self, jti: &str) -> Result<String, AuthError>;
}

pub trait TotpService: Send + Sync {
    fn generate_secret(&self) -> Result<String, AuthError>;
    fn otpauth_url(&self, email: &str, secret: &str) -> Result<String, AuthError>;
    fn verify_code(&self, secret: &str, code: &str, now: DateTime<Utc>) -> Result<bool, AuthError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait AuthAttemptLimiter: Send + Sync {
    fn check(&self, key: &str, now: DateTime<Utc>) -> Result<(), AuthError>;
    fn record_failure(&self, key: &str, now: DateTime<Utc>);
    fn record_success(&self, key: &str);
}
