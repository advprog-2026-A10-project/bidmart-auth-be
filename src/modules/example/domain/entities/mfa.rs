use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaTicket {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ticket_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl MfaTicket {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        ticket_hash: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            ticket_hash,
            created_at,
            expires_at,
            consumed_at: None,
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailMfaCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub invalidated_at: Option<DateTime<Utc>>,
}

impl EmailMfaCode {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        code_hash: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            code_hash,
            created_at,
            expires_at,
            consumed_at: None,
            invalidated_at: None,
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub jti_hash: String,
    pub mfa_satisfied: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSetup {
    pub id: Uuid,
    pub user_id: Uuid,
    pub setup_ticket_hash: String,
    pub secret: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl TotpSetup {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}
