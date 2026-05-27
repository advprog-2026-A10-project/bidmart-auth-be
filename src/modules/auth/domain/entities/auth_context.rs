use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUserContext {
    pub user_id: Uuid,
    pub mfa_satisfied: bool,
    pub session_jti_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAccessToken {
    pub token: String,
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}
