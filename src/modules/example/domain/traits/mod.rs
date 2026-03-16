use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::modules::example::domain::entities::{EmailVerificationToken, User};
use crate::modules::example::domain::errors::AuthError;

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
    async fn consume(&self, token_id: Uuid, consumed_at: DateTime<Utc>) -> Result<(), AuthError>;
    async fn invalidate_active_tokens_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, raw_password: &str) -> Result<String, AuthError>;
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

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
