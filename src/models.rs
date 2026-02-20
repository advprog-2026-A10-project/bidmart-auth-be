use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub status: String,
    pub mfa_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub status: String,
    pub mfa_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserRecord> for PublicUser {
    fn from(value: UserRecord) -> Self {
        Self {
            id: value.id,
            email: value.email,
            status: value.status,
            mfa_enabled: value.mfa_enabled,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub address: Option<String>,
    pub postal_code: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in_minutes: i64,
    pub user: PublicUser,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::{PublicUser, UserRecord};

    #[test]
    fn user_record_converts_to_public_user() {
        let now = Utc::now();
        let record = UserRecord {
            id: Uuid::new_v4(),
            email: "user@example.com".to_owned(),
            password_hash: "hash".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: true,
            created_at: now,
            updated_at: now,
        };

        let public: PublicUser = record.clone().into();
        assert_eq!(public.id, record.id);
        assert_eq!(public.email, record.email);
        assert_eq!(public.status, record.status);
        assert_eq!(public.mfa_enabled, record.mfa_enabled);
        assert_eq!(public.created_at, record.created_at);
        assert_eq!(public.updated_at, record.updated_at);
    }
}
