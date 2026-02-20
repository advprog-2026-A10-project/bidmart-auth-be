use std::env;

use anyhow::{Context, anyhow};

#[derive(Debug, Clone)]
pub struct Config {
    pub app_host: String,
    pub app_port: u16,
    pub database_url: String,
    pub database_max_connections: u32,
    pub jwt_secret: String,
    pub jwt_expiry_minutes: i64,
    pub cors_origin: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let app_host = env_var_or_default("APP_HOST", "0.0.0.0");
        let app_port = parse_env_or_default("APP_PORT", 8080)?;
        let database_url = env_var_required("DATABASE_URL")?;
        let database_max_connections = parse_env_or_default("DB_MAX_CONNECTIONS", 10)?;
        let jwt_secret = env_var_required("JWT_SECRET")?;
        let jwt_expiry_minutes = parse_env_or_default("JWT_EXPIRY_MINUTES", 60)?;
        let cors_origin = env_var_or_default("CORS_ORIGIN", "*");

        if jwt_secret.len() < 32 {
            return Err(anyhow!(
                "JWT_SECRET must be at least 32 characters for HS256"
            ));
        }

        Ok(Self {
            app_host,
            app_port,
            database_url,
            database_max_connections,
            jwt_secret,
            jwt_expiry_minutes,
            cors_origin,
        })
    }
}

fn env_var_required(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

fn env_var_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn parse_env_or_default<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + Copy + ToString,
    <T as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse::<T>()
        .with_context(|| format!("invalid value for {key}: {raw}"))
}
