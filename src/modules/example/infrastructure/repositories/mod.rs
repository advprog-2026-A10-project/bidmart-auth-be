use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::{Row, Transaction};
use uuid::Uuid;

use crate::modules::auth::domain::entities::{EmailVerificationToken, User, UserStatus};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{EmailVerificationTokenRepository, UserRepository};

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
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            status: UserStatus::from_db_value(row.get::<String, _>("status").as_str()),
            email_verified_at: row.get("email_verified_at"),
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
                u.email,
                u.password_hash,
                u.status::text AS status,
                u.email_verified_at,
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
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4::user_status, $5, $6, $7)
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.status.as_db_value())
        .bind(user.email_verified_at)
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
                u.email,
                u.password_hash,
                u.status::text AS status,
                u.email_verified_at,
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
                status = 'ACTIVE',
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
}

#[derive(Clone)]
pub struct PostgresEmailVerificationTokenRepository {
    pool: PgPool,
}

impl PostgresEmailVerificationTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_token(row: sqlx::postgres::PgRow) -> EmailVerificationToken {
        EmailVerificationToken {
            id: row.get("id"),
            user_id: row.get("user_id"),
            token_hash: row.get("token_hash"),
            created_at: row.get("created_at"),
            expires_at: row.get("expired_at"),
            consumed_at: row.get("consumed_at"),
            invalidated_at: row.get("invalidated_at"),
        }
    }
}

#[async_trait]
impl EmailVerificationTokenRepository for PostgresEmailVerificationTokenRepository {
    async fn save(&self, token: EmailVerificationToken) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO tokens (
                id,
                user_id,
                type,
                token_hash,
                expired_at,
                created_at,
                consumed_at,
                invalidated_at
            ) VALUES ($1, $2, 'EMAIL_VERIFICATION', $3, $4, $5, $6, $7)
            "#,
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at)
        .bind(token.created_at)
        .bind(token.consumed_at)
        .bind(token.invalidated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(())
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, token_hash, created_at, expired_at, consumed_at, invalidated_at
            FROM tokens
            WHERE type = 'EMAIL_VERIFICATION' AND token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row.map(Self::row_to_token))
    }

    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, token_hash, created_at, expired_at, consumed_at, invalidated_at
            FROM tokens
            WHERE
                type = 'EMAIL_VERIFICATION'
                AND user_id = $1
                AND consumed_at IS NULL
                AND invalidated_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row.map(Self::row_to_token))
    }

    async fn consume(&self, token_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE tokens
            SET consumed_at = $2
            WHERE
                id = $1
                AND type = 'EMAIL_VERIFICATION'
                AND consumed_at IS NULL
                AND invalidated_at IS NULL
            "#,
        )
        .bind(token_id)
        .bind(consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        Ok(rows_affected == 1)
    }

    async fn invalidate_active_tokens_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE tokens
            SET invalidated_at = $2
            WHERE
                user_id = $1
                AND type = 'EMAIL_VERIFICATION'
                AND consumed_at IS NULL
                AND invalidated_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(invalidated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(())
    }
}

async fn insert_or_update_profile(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    user: &User,
) -> Result<(), AuthError> {
    sqlx::query(
        r#"
        INSERT INTO user_profiles (user_id, first_name, last_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id) DO UPDATE
        SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name
        "#,
    )
    .bind(user.id)
    .bind(&user.first_name)
    .bind(&user.last_name)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

fn map_database_error(error: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23505") {
            return AuthError::EmailAlreadyExists;
        }
    }

    AuthError::DependencyFailure("database operation failed".to_string())
}
