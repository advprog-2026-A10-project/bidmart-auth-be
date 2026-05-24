use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let database_url =
        std::env::var("APP_DATABASE_URL").context("APP_DATABASE_URL is not set")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .context("failed to connect to database")?;

    // Keep this list explicit so we avoid touching sqlx migration metadata
    // tables and only reset application data.
    sqlx::query(
        r#"
        TRUNCATE TABLE
            role_permissions,
            permissions,
            roles,
            notification_preferences,
            totp_setups,
            email_mfa_codes,
            mfa_tickets,
            tokens,
            sessions,
            user_profiles,
            users
        RESTART IDENTITY CASCADE
        "#,
    )
    .execute(&pool)
    .await
    .context("failed to truncate application tables")?;

    println!("Database reset completed.");
    Ok(())
}

