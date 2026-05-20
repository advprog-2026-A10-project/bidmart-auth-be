use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Disabled,
    PendingVerification,
}

impl UserStatus {
    pub fn as_db_value(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Disabled => "DISABLED",
            Self::PendingVerification => "PENDING_VERIFICATION",
        }
    }

    pub fn from_db_value(value: &str) -> Self {
        match value {
            "ACTIVE" => Self::Active,
            "DISABLED" => Self::Disabled,
            _ => Self::PendingVerification,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: Option<String>,
    pub address: String,
    pub postal_code: String,
    pub email: String,
    pub password_hash: String,
    pub status: UserStatus,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub mfa_email_enabled: bool,
    pub mfa_totp_enabled: bool,
    pub mfa_totp_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(
        id: Uuid,
        name: &str,
        email: String,
        password_hash: String,
        now: DateTime<Utc>,
    ) -> Self {
        let (first_name, last_name) = split_name(name).unwrap_or_else(|| ("".to_string(), None));
        Self {
            id,
            first_name,
            last_name,
            address: String::new(),
            postal_code: String::new(),
            email,
            password_hash,
            status: UserStatus::PendingVerification,
            email_verified_at: None,
            mfa_email_enabled: false,
            mfa_totp_enabled: false,
            mfa_totp_secret: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    pub fn display_name(&self) -> String {
        match &self.last_name {
            Some(last_name) if !last_name.is_empty() => {
                format!("{} {}", self.first_name, last_name)
            }
            _ => self.first_name.clone(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }

    pub fn has_mfa_enabled(&self) -> bool {
        self.mfa_email_enabled || self.mfa_totp_enabled
    }
}

pub fn normalize_name(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    Some(parts.join(" "))
}

fn split_name(name: &str) -> Option<(String, Option<String>)> {
    let normalized = normalize_name(name)?;
    let mut parts = normalized.splitn(2, ' ');
    let first_name = parts.next()?.to_string();
    let last_name = parts.next().map(str::to_string);
    Some((first_name, last_name))
}
