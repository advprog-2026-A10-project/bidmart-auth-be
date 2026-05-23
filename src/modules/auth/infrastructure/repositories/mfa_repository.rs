use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::{
    EmailMfaCode, EmailMfaCodePurpose, MfaTicket, TotpSetup,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    EmailMfaCodeRepository, MfaTicketRepository, TotpSetupRepository,
};

use super::map_database_error;

#[derive(Clone)]
pub struct PostgresMfaTicketRepository {
    pool: PgPool,
}

impl PostgresMfaTicketRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_ticket(row: sqlx::postgres::PgRow) -> MfaTicket {
        MfaTicket {
            id: row.get("id"),
            user_id: row.get("user_id"),
            ticket_hash: row.get("ticket_hash"),
            created_at: row.get("created_at"),
            expires_at: row.get("expired_at"),
            consumed_at: row.get("consumed_at"),
        }
    }
}

#[async_trait]
impl MfaTicketRepository for PostgresMfaTicketRepository {
    async fn save(&self, ticket: MfaTicket) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO mfa_tickets (id, user_id, ticket_hash, created_at, expired_at, consumed_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(ticket.id)
        .bind(ticket.user_id)
        .bind(ticket.ticket_hash)
        .bind(ticket.created_at)
        .bind(ticket.expires_at)
        .bind(ticket.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<MfaTicket>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, ticket_hash, created_at, expired_at, consumed_at
            FROM mfa_tickets
            WHERE ticket_hash = $1
            "#,
        )
        .bind(ticket_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(row.map(Self::row_to_ticket))
    }

    async fn consume(&self, ticket_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE mfa_tickets
            SET consumed_at = $2
            WHERE id = $1 AND consumed_at IS NULL
            "#,
        )
        .bind(ticket_id)
        .bind(consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        Ok(rows_affected == 1)
    }
}

#[derive(Clone)]
pub struct PostgresEmailMfaCodeRepository {
    pool: PgPool,
}

impl PostgresEmailMfaCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_code(row: sqlx::postgres::PgRow) -> EmailMfaCode {
        let purpose: String = row.get("purpose");
        EmailMfaCode {
            id: row.get("id"),
            user_id: row.get("user_id"),
            code_hash: row.get("code_hash"),
            purpose: EmailMfaCodePurpose::from_storage_value(&purpose)
                .unwrap_or(EmailMfaCodePurpose::Login),
            created_at: row.get("created_at"),
            expires_at: row.get("expired_at"),
            consumed_at: row.get("consumed_at"),
            invalidated_at: row.get("invalidated_at"),
        }
    }
}

#[async_trait]
impl EmailMfaCodeRepository for PostgresEmailMfaCodeRepository {
    async fn save(&self, code: EmailMfaCode) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO email_mfa_codes (
                id, user_id, code_hash, purpose, created_at, expired_at, consumed_at, invalidated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(code.id)
        .bind(code.user_id)
        .bind(code.code_hash)
        .bind(code.purpose.as_str())
        .bind(code.created_at)
        .bind(code.expires_at)
        .bind(code.consumed_at)
        .bind(code.invalidated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn find_by_code_hash(&self, code_hash: &str) -> Result<Option<EmailMfaCode>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, code_hash, purpose, created_at, expired_at, consumed_at, invalidated_at
            FROM email_mfa_codes
            WHERE code_hash = $1
            "#,
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(row.map(Self::row_to_code))
    }

    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
        purpose: EmailMfaCodePurpose,
    ) -> Result<Option<EmailMfaCode>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, code_hash, purpose, created_at, expired_at, consumed_at, invalidated_at
            FROM email_mfa_codes
            WHERE user_id = $1
              AND purpose = $2
              AND consumed_at IS NULL
              AND invalidated_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(purpose.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(row.map(Self::row_to_code))
    }

    async fn consume(&self, code_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE email_mfa_codes
            SET consumed_at = $2
            WHERE id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL
            "#,
        )
        .bind(code_id)
        .bind(consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        Ok(rows_affected == 1)
    }

    async fn invalidate_active_codes_for_user(
        &self,
        user_id: Uuid,
        purpose: EmailMfaCodePurpose,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE email_mfa_codes
            SET invalidated_at = $3
            WHERE user_id = $1
              AND purpose = $2
              AND consumed_at IS NULL
              AND invalidated_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(purpose.as_str())
        .bind(invalidated_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresTotpSetupRepository {
    pool: PgPool,
}

impl PostgresTotpSetupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TotpSetupRepository for PostgresTotpSetupRepository {
    async fn save(&self, setup: TotpSetup) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO totp_setups (
                id, user_id, setup_ticket_hash, secret, created_at, expired_at, consumed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(setup.id)
        .bind(setup.user_id)
        .bind(setup.setup_ticket_hash)
        .bind(setup.secret)
        .bind(setup.created_at)
        .bind(setup.expires_at)
        .bind(setup.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<TotpSetup>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, setup_ticket_hash, secret, created_at, expired_at, consumed_at
            FROM totp_setups
            WHERE setup_ticket_hash = $1
            "#,
        )
        .bind(ticket_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(row.map(|row| TotpSetup {
            id: row.get("id"),
            user_id: row.get("user_id"),
            setup_ticket_hash: row.get("setup_ticket_hash"),
            secret: row.get("secret"),
            created_at: row.get("created_at"),
            expires_at: row.get("expired_at"),
            consumed_at: row.get("consumed_at"),
        }))
    }

    async fn consume(&self, setup_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE totp_setups
            SET consumed_at = $2
            WHERE id = $1 AND consumed_at IS NULL
            "#,
        )
        .bind(setup_id)
        .bind(consumed_at)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        Ok(rows_affected == 1)
    }
}
