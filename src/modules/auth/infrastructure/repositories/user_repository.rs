use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::{User, UserStatus};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::UserRepository;

use super::{insert_or_update_profile, map_database_error};

#[derive(Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_user(row: sqlx::postgres::PgRow) -> User {
        User {
            id: row.get("id"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            address: row.get("address"),
            postal_code: row.get("postal_code"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            status: UserStatus::from_db_value(row.get::<String, _>("status").as_str()),
            email_verified_at: row.get("email_verified_at"),
            mfa_email_enabled: row.get("mfa_email_enabled"),
            mfa_totp_enabled: row.get("mfa_totp_enabled"),
            mfa_totp_secret: row.get("mfa_totp_secret"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_email(&self, normalized_email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT
                u.id,
                COALESCE(p.first_name, '') AS first_name,
                p.last_name,
                COALESCE(p.address, '') AS address,
                COALESCE(p.postal_code, '') AS postal_code,
                u.email,
                u.password_hash,
                u.status::text AS status,
                u.email_verified_at,
                u.mfa_email_enabled,
                u.mfa_totp_enabled,
                u.mfa_totp_secret,
                u.created_at,
                u.updated_at
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
            WHERE u.email = $1
            "#,
        )
        .bind(normalized_email)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row.map(Self::row_to_user))
    }

    async fn create(&self, user: User) -> Result<User, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;

        sqlx::query(
            r#"
            INSERT INTO users (
                id,
                email,
                password_hash,
                status,
                email_verified_at,
                mfa_email_enabled,
                mfa_totp_enabled,
                mfa_totp_secret,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4::user_status, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.status.as_db_value())
        .bind(user.email_verified_at)
        .bind(user.mfa_email_enabled)
        .bind(user.mfa_totp_enabled)
        .bind(&user.mfa_totp_secret)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;

        insert_or_update_profile(&mut transaction, &user).await?;

        transaction.commit().await.map_err(map_database_error)?;

        Ok(user)
    }

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT
                u.id,
                COALESCE(p.first_name, '') AS first_name,
                p.last_name,
                COALESCE(p.address, '') AS address,
                COALESCE(p.postal_code, '') AS postal_code,
                u.email,
                u.password_hash,
                u.status::text AS status,
                u.email_verified_at,
                u.mfa_email_enabled,
                u.mfa_totp_enabled,
                u.mfa_totp_secret,
                u.created_at,
                u.updated_at
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
            WHERE u.id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row.map(Self::row_to_user))
    }

    async fn mark_email_verified(
        &self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET
                status = CASE
                    WHEN status = 'PENDING_VERIFICATION' THEN 'ACTIVE'::user_status
                    ELSE status
                END,
                email_verified_at = $2,
                updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(verified_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn update_mfa_email_enabled(
        &self,
        user_id: Uuid,
        enabled: bool,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET mfa_email_enabled = $2, updated_at = $3
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(enabled)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn update_mfa_totp(
        &self,
        user_id: Uuid,
        enabled: bool,
        secret: Option<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET
                mfa_totp_enabled = $2,
                mfa_totp_secret = $3,
                updated_at = $4
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(enabled)
        .bind(secret)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn disable_mfa(&self, user_id: Uuid, updated_at: DateTime<Utc>) -> Result<(), AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET
                mfa_email_enabled = false,
                mfa_totp_enabled = false,
                mfa_totp_secret = NULL,
                updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn update_profile(
        &self,
        user_id: Uuid,
        name: &str,
        address: &str,
        postal_code: &str,
        updated_at: DateTime<Utc>,
    ) -> Result<User, AuthError> {
        let mut user = self
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let normalized_name = crate::modules::auth::domain::entities::user::normalize_name(name)
            .ok_or(AuthError::InvalidName)?;
        let mut parts = normalized_name.splitn(2, ' ');
        user.first_name = parts.next().unwrap_or_default().to_string();
        user.last_name = parts.next().map(str::to_string);
        user.address = address.trim().to_string();
        user.postal_code = postal_code.trim().to_string();
        user.updated_at = updated_at;

        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        insert_or_update_profile(&mut transaction, &user).await?;
        sqlx::query("UPDATE users SET updated_at = $2 WHERE id = $1")
            .bind(user_id)
            .bind(updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        transaction.commit().await.map_err(map_database_error)?;
        Ok(user)
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $2, updated_at = $3
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }
}
