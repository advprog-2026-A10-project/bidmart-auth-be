use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use scrypt::password_hash::rand_core::OsRng;
use scrypt::password_hash::SaltString;
use scrypt::{password_hash::PasswordHasher as _, Scrypt};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

struct SeedUser<'a> {
    email: &'a str,
    password: &'a str,
    status: &'a str,
    email_verified_at: Option<DateTime<Utc>>,
    first_name: &'a str,
    last_name: Option<&'a str>,
    address: &'a str,
    postal_code: &'a str,
}

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

    let now = Utc::now();
    let users = vec![
        SeedUser {
            email: "disabled.user@bidmart.dev",
            password: "Password123!",
            status: "DISABLED",
            email_verified_at: Some(now),
            first_name: "Disabled",
            last_name: Some("User"),
            address: "Yogyakarta",
            postal_code: "55111",
        },
        SeedUser {
            email: "pending.user@bidmart.dev",
            password: "Password123!",
            status: "PENDING_VERIFICATION",
            email_verified_at: None,
            first_name: "Pending",
            last_name: Some("User"),
            address: "Surabaya",
            postal_code: "60111",
        },
        SeedUser {
            email: "pending.verified@bidmart.dev",
            password: "Password123!",
            status: "PENDING_VERIFICATION",
            email_verified_at: Some(now),
            first_name: "Pending",
            last_name: Some("Verified"),
            address: "Malang",
            postal_code: "65111",
        },
        SeedUser {
            email: "disabled.unverified@bidmart.dev",
            password: "Password123!",
            status: "DISABLED",
            email_verified_at: None,
            first_name: "Disabled",
            last_name: Some("Unverified"),
            address: "Semarang",
            postal_code: "50111",
        },
        SeedUser {
            email: "active.verified@bidmart.dev",
            password: "Password123!",
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Active",
            last_name: Some("Verified"),
            address: "Denpasar",
            postal_code: "80221",
        },
    ];

    for user in users {
        let password_hash = hash_password(user.password)?;
        let user_id = upsert_user(
            &pool,
            user.email,
            &password_hash,
            user.status,
            user.email_verified_at,
            now,
        )
        .await?;

        upsert_user_profile(
            &pool,
            user_id,
            user.first_name,
            user.last_name,
            user.address,
            user.postal_code,
        )
        .await?;

        upsert_notification_preferences(&pool, user_id, now).await?;
    }

    // Baseline authorization rows; harmless if rerun.
    sqlx::query("INSERT INTO roles(name) VALUES ('admin'), ('user') ON CONFLICT(name) DO NOTHING")
        .execute(&pool)
        .await
        .context("failed to seed roles")?;

    println!("Database seed completed.");
    println!("Seeded users (password for all: Password123!):");
    println!("- disabled.user@bidmart.dev (DISABLED, verified)");
    println!("- pending.user@bidmart.dev (PENDING_VERIFICATION, unverified)");
    println!("- pending.verified@bidmart.dev (PENDING_VERIFICATION, verified)");
    println!("- disabled.unverified@bidmart.dev (DISABLED, unverified)");
    println!("- active.verified@bidmart.dev (ACTIVE, verified)");
    Ok(())
}

fn hash_password(raw_password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(raw_password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("failed to hash seed password: {error}"))
}

async fn upsert_user(
    pool: &sqlx::PgPool,
    email: &str,
    password_hash: &str,
    status: &str,
    email_verified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<Uuid> {
    let row = sqlx::query(
        r#"
        INSERT INTO users (
            email,
            password_hash,
            status,
            email_verified_at,
            mfa_email_enabled,
            mfa_totp_enabled,
            mfa_totp_secret,
            created_at,
            updated_at
        ) VALUES ($1, $2, $3::user_status, $4, false, false, NULL, $5, $5)
        ON CONFLICT (email)
        DO UPDATE SET
            password_hash = EXCLUDED.password_hash,
            status = EXCLUDED.status,
            email_verified_at = EXCLUDED.email_verified_at,
            mfa_email_enabled = false,
            mfa_totp_enabled = false,
            mfa_totp_secret = NULL,
            updated_at = EXCLUDED.updated_at
        RETURNING id
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(status)
    .bind(email_verified_at)
    .bind(now)
    .fetch_one(pool)
    .await
    .with_context(|| format!("failed to upsert user: {email}"))?;

    Ok(sqlx::Row::get(&row, "id"))
}

async fn upsert_user_profile(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    first_name: &str,
    last_name: Option<&str>,
    address: &str,
    postal_code: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO user_profiles (
            user_id,
            first_name,
            last_name,
            address,
            postal_code,
            avatar_url
        ) VALUES ($1, $2, $3, $4, $5, NULL)
        ON CONFLICT (user_id)
        DO UPDATE SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            address = EXCLUDED.address,
            postal_code = EXCLUDED.postal_code
        "#,
    )
    .bind(user_id)
    .bind(first_name)
    .bind(last_name)
    .bind(address)
    .bind(postal_code)
    .execute(pool)
    .await
    .with_context(|| format!("failed to upsert profile for user_id={user_id}"))?;

    Ok(())
}

async fn upsert_notification_preferences(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO notification_preferences (
            user_id,
            email_notifications,
            push_notifications,
            marketing_emails,
            security_alerts,
            updated_at
        ) VALUES ($1, true, true, false, true, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET
            email_notifications = EXCLUDED.email_notifications,
            push_notifications = EXCLUDED.push_notifications,
            marketing_emails = EXCLUDED.marketing_emails,
            security_alerts = EXCLUDED.security_alerts,
            updated_at = EXCLUDED.updated_at
        "#,
    )
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await
    .with_context(|| format!("failed to upsert notification preferences for user_id={user_id}"))?;

    Ok(())
}
