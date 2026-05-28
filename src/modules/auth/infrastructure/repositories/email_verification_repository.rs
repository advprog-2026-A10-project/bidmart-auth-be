use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::EmailVerificationToken;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::EmailVerificationTokenRepository;

use super::map_database_error;

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
