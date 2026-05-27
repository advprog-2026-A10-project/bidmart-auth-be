use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::PasswordResetToken;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    PasswordResetCompletionRepository, PasswordResetTokenRepository,
};

use super::map_database_error;

#[derive(Clone)]
pub struct PostgresPasswordResetTokenRepository {
    pool: PgPool,
}

impl PostgresPasswordResetTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_token(row: sqlx::postgres::PgRow) -> PasswordResetToken {
        PasswordResetToken {
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
impl PasswordResetTokenRepository for PostgresPasswordResetTokenRepository {
    async fn save(&self, token: PasswordResetToken) -> Result<(), AuthError> {
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
            ) VALUES ($1, $2, 'PASSWORD_RESET', $3, $4, $5, $6, $7)
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
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, token_hash, created_at, expired_at, consumed_at, invalidated_at
            FROM tokens
            WHERE type = 'PASSWORD_RESET' AND token_hash = $1
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
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, token_hash, created_at, expired_at, consumed_at, invalidated_at
            FROM tokens
            WHERE
                type = 'PASSWORD_RESET'
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
                AND type = 'PASSWORD_RESET'
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

#[async_trait]
impl PasswordResetCompletionRepository for PostgresPasswordResetTokenRepository {
    async fn complete_password_reset(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        password_hash: String,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;

        let token_rows = sqlx::query(
            r#"
            UPDATE tokens
            SET consumed_at = $2
            WHERE
                id = $1
                AND user_id = $3
                AND type = 'PASSWORD_RESET'
                AND consumed_at IS NULL
                AND invalidated_at IS NULL
                AND expired_at > $2
            "#,
        )
        .bind(token_id)
        .bind(completed_at)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if token_rows != 1 {
            transaction.rollback().await.map_err(map_database_error)?;
            return Ok(false);
        }

        let user_rows = sqlx::query(
            r#"
            UPDATE users
            SET
                password_hash = $2,
                status = CASE
                    WHEN status = 'PENDING_VERIFICATION' THEN 'ACTIVE'::user_status
                    ELSE status
                END,
                email_verified_at = COALESCE(email_verified_at, $3),
                updated_at = $3
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(completed_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        if user_rows != 1 {
            transaction.rollback().await.map_err(map_database_error)?;
            return Err(AuthError::UserNotFound);
        }

        sqlx::query(
            r#"
            UPDATE sessions
            SET expired_at = $2
            WHERE user_id = $1 AND expired_at > $2
            "#,
        )
        .bind(user_id)
        .bind(completed_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;

        transaction.commit().await.map_err(map_database_error)?;
        Ok(true)
    }
}
