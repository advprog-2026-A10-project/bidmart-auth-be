use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::{Row, Transaction};
use uuid::Uuid;

use crate::modules::auth::domain::entities::{
    AuthSession, EmailMfaCode, EmailMfaCodePurpose, EmailVerificationToken, MfaTicket,
    NotificationPreferences, PasswordResetToken, TotpSetup, User, UserStatus,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    EmailMfaCodeRepository, EmailVerificationTokenRepository, MfaTicketRepository,
    NotificationPreferencesRepository, PasswordResetCompletionRepository,
    PasswordResetTokenRepository, SessionRepository, TotpSetupRepository, UserRepository,
};

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
            SET password_hash = $2, updated_at = $3
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

async fn insert_or_update_profile(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    user: &User,
) -> Result<(), AuthError> {
    sqlx::query(
        r#"
        INSERT INTO user_profiles (user_id, first_name, last_name, address, postal_code)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE
        SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            address = EXCLUDED.address,
            postal_code = EXCLUDED.postal_code
        "#,
    )
    .bind(user.id)
    .bind(&user.first_name)
    .bind(&user.last_name)
    .bind(&user.address)
    .bind(&user.postal_code)
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

    async fn consume(
        &self,
        ticket_id: Uuid,
        consumed_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
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

    async fn revoke_current_session(
        &self,
        user_id: Uuid,
        current_jti_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE sessions
            SET expired_at = $3
            WHERE
                user_id = $1
                AND jti_hash = $2
                AND expired_at > $3
            "#,
        )
        .bind(user_id)
        .bind(current_jti_hash)
        .bind(now)
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

#[derive(Clone)]
pub struct PostgresNotificationPreferencesRepository {
    pool: PgPool,
}

impl PostgresNotificationPreferencesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NotificationPreferencesRepository for PostgresNotificationPreferencesRepository {
    async fn get_by_user_id(&self, user_id: Uuid) -> Result<NotificationPreferences, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT email_notifications, push_notifications, marketing_emails, security_alerts
            FROM notification_preferences
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row
            .map(|row| NotificationPreferences {
                email_notifications: row.get("email_notifications"),
                push_notifications: row.get("push_notifications"),
                marketing_emails: row.get("marketing_emails"),
                security_alerts: row.get("security_alerts"),
            })
            .unwrap_or_default())
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        preferences: NotificationPreferences,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO notification_preferences (
                user_id, email_notifications, push_notifications, marketing_emails, security_alerts
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE SET
                email_notifications = EXCLUDED.email_notifications,
                push_notifications = EXCLUDED.push_notifications,
                marketing_emails = EXCLUDED.marketing_emails,
                security_alerts = EXCLUDED.security_alerts,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(user_id)
        .bind(preferences.email_notifications)
        .bind(preferences.push_notifications)
        .bind(preferences.marketing_emails)
        .bind(preferences.security_alerts)
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
