use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::AuthSession;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::SessionRepository;

use super::map_database_error;

#[derive(Clone)]
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_session(row: sqlx::postgres::PgRow) -> AuthSession {
        AuthSession {
            id: row.get("id"),
            user_id: row.get("user_id"),
            jti_hash: row.get("jti_hash"),
            mfa_satisfied: row.get("mfa_satisfied"),
            device: row.get("device"),
            browser: row.get("browser"),
            os: row.get("os"),
            ip: row.get("ip"),
            location: row.get("location"),
            created_at: row.get("created_at"),
            last_active_at: row.get("last_active_at"),
            expires_at: row.get("expired_at"),
        }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, user_id, jti_hash, mfa_satisfied, device, browser, os, ip, location,
                expired_at, created_at, last_active_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(session.jti_hash)
        .bind(session.mfa_satisfied)
        .bind(session.device)
        .bind(session.browser)
        .bind(session.os)
        .bind(session.ip)
        .bind(session.location)
        .bind(session.expires_at)
        .bind(session.created_at)
        .bind(session.last_active_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn find_active_by_jti_hash(
        &self,
        jti_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, user_id, jti_hash, mfa_satisfied, device, browser, os, ip, location,
                created_at, last_active_at, expired_at
            FROM sessions
            WHERE jti_hash = $1 AND expired_at > $2
            "#,
        )
        .bind(jti_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(row.map(Self::row_to_session))
    }

    async fn touch_last_active(&self, jti_hash: &str, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE sessions
            SET last_active_at = $2
            WHERE jti_hash = $1 AND expired_at > $2
            "#,
        )
        .bind(jti_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn list_active_by_user_id(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<AuthSession>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, user_id, jti_hash, mfa_satisfied, device, browser, os, ip, location,
                created_at, last_active_at, expired_at
            FROM sessions
            WHERE user_id = $1 AND expired_at > $2
            ORDER BY last_active_at DESC
            "#,
        )
        .bind(user_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(rows.into_iter().map(Self::row_to_session).collect())
    }

    async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        current_jti_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE sessions
            SET expired_at = $3
            WHERE
                user_id = $1
                AND id = $2
                AND expired_at > $3
                AND ($4::text IS NULL OR jti_hash <> $4)
            "#,
        )
        .bind(user_id)
        .bind(session_id)
        .bind(now)
        .bind(current_jti_hash)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        Ok(rows_affected == 1)
    }

    async fn revoke_all_other_sessions(
        &self,
        user_id: Uuid,
        current_jti_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE sessions
            SET expired_at = $2
            WHERE
                user_id = $1
                AND expired_at > $2
                AND ($3::text IS NULL OR jti_hash <> $3)
            "#,
        )
        .bind(user_id)
        .bind(now)
        .bind(current_jti_hash)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }
}
