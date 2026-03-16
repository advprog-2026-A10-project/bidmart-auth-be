use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(id: Uuid, email: String, password_hash: String, now: DateTime<Utc>) -> Self {
        Self {
            id,
            email,
            password_hash,
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}
