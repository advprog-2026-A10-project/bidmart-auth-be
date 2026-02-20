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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::Config;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const KEYS: [&str; 7] = [
        "APP_HOST",
        "APP_PORT",
        "DATABASE_URL",
        "DB_MAX_CONNECTIONS",
        "JWT_SECRET",
        "JWT_EXPIRY_MINUTES",
        "CORS_ORIGIN",
    ];

    fn set_var(key: &str, value: &str) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    fn remove_var(key: &str) {
        unsafe {
            std::env::remove_var(key);
        }
    }

    fn clear_config_env() {
        for key in KEYS {
            remove_var(key);
        }
    }

    fn set_base_env() {
        set_var("DATABASE_URL", "postgres://user:password@localhost/test");
        set_var("JWT_SECRET", "01234567890123456789012345678901");
    }

    #[test]
    fn from_env_uses_defaults() {
        let _guard = ENV_LOCK.lock().expect("lock");
        clear_config_env();
        set_base_env();

        let cfg = Config::from_env().expect("config should load");
        assert_eq!(cfg.app_host, "0.0.0.0");
        assert_eq!(cfg.app_port, 8080);
        assert_eq!(cfg.database_max_connections, 10);
        assert_eq!(cfg.jwt_expiry_minutes, 60);
        assert_eq!(cfg.cors_origin, "*");
    }

    #[test]
    fn from_env_reads_custom_values() {
        let _guard = ENV_LOCK.lock().expect("lock");
        clear_config_env();
        set_base_env();
        set_var("APP_HOST", "127.0.0.1");
        set_var("APP_PORT", "9090");
        set_var("DB_MAX_CONNECTIONS", "25");
        set_var("JWT_EXPIRY_MINUTES", "15");
        set_var("CORS_ORIGIN", "http://localhost:5173");

        let cfg = Config::from_env().expect("config should load");
        assert_eq!(cfg.app_host, "127.0.0.1");
        assert_eq!(cfg.app_port, 9090);
        assert_eq!(cfg.database_max_connections, 25);
        assert_eq!(cfg.jwt_expiry_minutes, 15);
        assert_eq!(cfg.cors_origin, "http://localhost:5173");
    }

    #[test]
    fn from_env_rejects_short_secret() {
        let _guard = ENV_LOCK.lock().expect("lock");
        clear_config_env();
        set_var("DATABASE_URL", "postgres://user:password@localhost/test");
        set_var("JWT_SECRET", "short-secret");

        let err = Config::from_env().expect_err("must reject weak secret");
        assert!(
            err.to_string()
                .contains("JWT_SECRET must be at least 32 characters")
        );
    }

    #[test]
    fn from_env_rejects_invalid_numeric_value() {
        let _guard = ENV_LOCK.lock().expect("lock");
        clear_config_env();
        set_base_env();
        set_var("APP_PORT", "invalid");

        let err = Config::from_env().expect_err("must reject invalid port");
        assert!(err.to_string().contains("invalid value for APP_PORT"));
    }

    #[test]
    fn from_env_requires_database_url() {
        let _guard = ENV_LOCK.lock().expect("lock");
        clear_config_env();
        set_var("JWT_SECRET", "01234567890123456789012345678901");

        let err = Config::from_env().expect_err("must require database url");
        assert!(err.to_string().contains("DATABASE_URL is required"));
    }
}
