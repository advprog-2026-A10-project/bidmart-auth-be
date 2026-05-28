pub mod authorization_repository;
pub mod email_verification_repository;
pub mod mfa_repository;
pub mod notification_repository;
pub mod password_reset_repository;
pub mod session_repository;
pub mod user_repository;

pub use authorization_repository::PostgresAuthorizationRepository;
pub use email_verification_repository::PostgresEmailVerificationTokenRepository;
pub use mfa_repository::{
    PostgresEmailMfaCodeRepository, PostgresMfaTicketRepository, PostgresTotpSetupRepository,
};
pub use notification_repository::PostgresNotificationPreferencesRepository;
pub use password_reset_repository::PostgresPasswordResetTokenRepository;
pub use session_repository::PostgresSessionRepository;
pub use user_repository::PostgresUserRepository;

use crate::modules::auth::domain::entities::User;
use crate::modules::auth::domain::errors::AuthError;
use sqlx::Transaction;

pub(super) async fn insert_or_update_profile(
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

pub(super) fn map_database_error(error: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23505") {
            return AuthError::EmailAlreadyExists;
        }
    }

    AuthError::DependencyFailure("database operation failed".to_string())
}
