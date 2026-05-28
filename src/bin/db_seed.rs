use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use scrypt::password_hash::rand_core::OsRng;
use scrypt::password_hash::SaltString;
use scrypt::{password_hash::PasswordHasher as _, Scrypt};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const DEFAULT_PASSWORD: &str = "Password123!";

const ADMIN_USER_ID: &str = "11111111-1111-4111-8111-111111111111";
const SELLER_HAKIM_ID: &str = "a6bf5e42-c500-4299-8607-891cb9f4c501";
const SELLER_NUSA_ID: &str = "fc5ea6c0-2bb7-4d82-bf66-d95e6cc1f502";
const SELLER_RAMA_ID: &str = "582d4da5-d50c-4c56-95bd-c971d8472503";
const SELLER_HOMELAB_ID: &str = "0b29758c-fb0f-4d3a-ab7b-bd66868c4504";
const SELLER_GAMEHAVEN_ID: &str = "32abf8ea-8e24-4896-bf3e-62a8d6a4f505";
const BUYER_AYU_ID: &str = "9d7f2c42-6b44-4a6a-92fe-1880d7b1a601";
const BUYER_BIMO_ID: &str = "8f3de4a9-ff1c-43b1-9f74-e527f66da602";
const BUYER_CITRA_ID: &str = "7ab4db3f-6ba2-41f4-91f5-b69e6e1df603";

struct SeedUser<'a> {
    id: &'a str,
    email: &'a str,
    password: &'a str,
    status: &'a str,
    email_verified_at: Option<DateTime<Utc>>,
    first_name: &'a str,
    last_name: Option<&'a str>,
    address: &'a str,
    postal_code: &'a str,
    roles: &'a [&'a str],
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("APP_DATABASE_URL").context("APP_DATABASE_URL is not set")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .context("failed to connect to database")?;

    seed_roles_and_permissions(&pool).await?;

    let now = Utc::now();
    let users = vec![
        SeedUser {
            id: ADMIN_USER_ID,
            email: "admin@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "System",
            last_name: Some("Admin"),
            address: "Jakarta",
            postal_code: "10110",
            roles: &["ADMIN"],
        },
        SeedUser {
            id: SELLER_HAKIM_ID,
            email: "hakim.store@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Hakim",
            last_name: Some("Store"),
            address: "Bandung",
            postal_code: "40111",
            roles: &["USER"],
        },
        SeedUser {
            id: SELLER_NUSA_ID,
            email: "nusa.camera@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Nusa",
            last_name: Some("Camera"),
            address: "Jakarta Selatan",
            postal_code: "12190",
            roles: &["USER"],
        },
        SeedUser {
            id: SELLER_RAMA_ID,
            email: "rama.outfit@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Rama",
            last_name: Some("Outfit"),
            address: "Depok",
            postal_code: "16424",
            roles: &["USER"],
        },
        SeedUser {
            id: SELLER_HOMELAB_ID,
            email: "homelab@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Home",
            last_name: Some("Lab"),
            address: "Yogyakarta",
            postal_code: "55281",
            roles: &["USER"],
        },
        SeedUser {
            id: SELLER_GAMEHAVEN_ID,
            email: "game.haven@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Game",
            last_name: Some("Haven"),
            address: "Surabaya",
            postal_code: "60226",
            roles: &["USER"],
        },
        SeedUser {
            id: BUYER_AYU_ID,
            email: "ayu.pratama@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Ayu",
            last_name: Some("Pratama"),
            address: "Bekasi",
            postal_code: "17112",
            roles: &["USER"],
        },
        SeedUser {
            id: BUYER_BIMO_ID,
            email: "bimo.santoso@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Bimo",
            last_name: Some("Santoso"),
            address: "Tangerang",
            postal_code: "15111",
            roles: &["USER"],
        },
        SeedUser {
            id: BUYER_CITRA_ID,
            email: "citra.anggraini@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Citra",
            last_name: Some("Anggraini"),
            address: "Bogor",
            postal_code: "16128",
            roles: &["USER"],
        },
        SeedUser {
            id: "11f58f55-174c-4c9b-8b1f-6cbb4dbf6701",
            email: "disabled.user@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "DISABLED",
            email_verified_at: Some(now),
            first_name: "Disabled",
            last_name: Some("User"),
            address: "Yogyakarta",
            postal_code: "55111",
            roles: &["USER"],
        },
        SeedUser {
            id: "6db2940d-e34f-47c4-b0f4-5b18ccf5b702",
            email: "pending.user@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "PENDING_VERIFICATION",
            email_verified_at: None,
            first_name: "Pending",
            last_name: Some("User"),
            address: "Surabaya",
            postal_code: "60111",
            roles: &["USER"],
        },
        SeedUser {
            id: "4ff6d128-aad5-43fa-9ca3-412d4df60e03",
            email: "pending.verified@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "PENDING_VERIFICATION",
            email_verified_at: Some(now),
            first_name: "Pending",
            last_name: Some("Verified"),
            address: "Malang",
            postal_code: "65111",
            roles: &["USER"],
        },
        SeedUser {
            id: "1f2d1ffd-667f-4aac-a690-d99f31c90f04",
            email: "disabled.unverified@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "DISABLED",
            email_verified_at: None,
            first_name: "Disabled",
            last_name: Some("Unverified"),
            address: "Semarang",
            postal_code: "50111",
            roles: &["USER"],
        },
        SeedUser {
            id: "6b49a298-d4de-4c53-b66f-b3c8beec2d05",
            email: "active.verified@bidmart.dev",
            password: DEFAULT_PASSWORD,
            status: "ACTIVE",
            email_verified_at: Some(now),
            first_name: "Active",
            last_name: Some("Verified"),
            address: "Denpasar",
            postal_code: "80221",
            roles: &["USER"],
        },
    ];

    for user in users {
        let user_id = parse_uuid(user.id, "seed user id")?;

        // Keep IDs deterministic for cross-service seeds.
        sqlx::query("DELETE FROM users WHERE email = $1 AND id <> $2")
            .bind(user.email)
            .bind(user_id)
            .execute(&pool)
            .await
            .with_context(|| format!("failed to normalize existing user row for {}", user.email))?;

        let password_hash = hash_password(user.password)?;
        let persisted_user_id = upsert_user(
            &pool,
            user_id,
            user.email,
            &password_hash,
            user.status,
            user.email_verified_at,
            now,
        )
        .await?;

        upsert_user_profile(
            &pool,
            persisted_user_id,
            user.first_name,
            user.last_name,
            user.address,
            user.postal_code,
        )
        .await?;

        upsert_notification_preferences(&pool, persisted_user_id, now).await?;
        assign_roles(&pool, persisted_user_id, user.roles).await?;
    }

    println!("Database seed completed.");
    println!("Default password for all seeded users: {DEFAULT_PASSWORD}");
    println!("Admin account: admin@bidmart.dev (role: ADMIN)");
    Ok(())
}

fn parse_uuid(raw: &str, field: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).with_context(|| format!("invalid {field}: {raw}"))
}

fn hash_password(raw_password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(raw_password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("failed to hash seed password: {error}"))
}

async fn seed_roles_and_permissions(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO roles(name)
        VALUES ('ADMIN'), ('USER')
        ON CONFLICT(name) DO NOTHING
        "#,
    )
    .execute(pool)
    .await
    .context("failed to seed roles")?;

    sqlx::query(
        r#"
        INSERT INTO permissions(slug)
        VALUES
            ('admin:access'),
            ('admin:auth:read'),
            ('user:suspend'),
            ('listing:moderate'),
            ('order:intervene'),
            ('wallet:adjust'),
            ('category:manage')
        ON CONFLICT(slug) DO NOTHING
        "#,
    )
    .execute(pool)
    .await
    .context("failed to seed permissions")?;

    sqlx::query(
        r#"
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r
        JOIN permissions p ON p.slug IN (
            'admin:access',
            'admin:auth:read',
            'user:suspend',
            'listing:moderate',
            'order:intervene',
            'wallet:adjust',
            'category:manage'
        )
        WHERE UPPER(r.name) = 'ADMIN'
        ON CONFLICT (role_id, permission_id) DO NOTHING
        "#,
    )
    .execute(pool)
    .await
    .context("failed to seed role permissions for ADMIN")?;

    Ok(())
}

async fn assign_roles(pool: &sqlx::PgPool, user_id: Uuid, roles: &[&str]) -> Result<()> {
    for role_name in roles {
        sqlx::query(
            r#"
            INSERT INTO user_roles (user_id, role_id)
            SELECT $1, r.id
            FROM roles r
            WHERE UPPER(r.name) = UPPER($2)
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(*role_name)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to assign role {} to user_id={} during seed",
                role_name, user_id
            )
        })?;
    }

    Ok(())
}

async fn upsert_user(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    email: &str,
    password_hash: &str,
    status: &str,
    email_verified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<Uuid> {
    let row = sqlx::query(
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
        ) VALUES ($1, $2, $3, $4::user_status, $5, false, false, NULL, $6, $6)
        ON CONFLICT (id)
        DO UPDATE SET
            email = EXCLUDED.email,
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
    .bind(user_id)
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
