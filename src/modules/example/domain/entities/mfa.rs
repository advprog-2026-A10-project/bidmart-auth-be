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
pub enum EmailMfaCodePurpose {
    Login,
    Setup,
}

impl EmailMfaCodePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Setup => "setup",
        }
    }

    pub fn from_storage_value(value: &str) -> Option<Self> {
        match value {
            "login" => Some(Self::Login),
            "setup" => Some(Self::Setup),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailMfaCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub purpose: EmailMfaCodePurpose,
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
        purpose: EmailMfaCodePurpose,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            code_hash,
            purpose,
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
    pub device: String,
    pub browser: String,
    pub os: String,
    pub ip: String,
    pub location: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationPreferences {
    pub email_notifications: bool,
    pub push_notifications: bool,
    pub marketing_emails: bool,
    pub security_alerts: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            email_notifications: true,
            push_notifications: true,
            marketing_emails: false,
            security_alerts: true,
        }
    }
}
