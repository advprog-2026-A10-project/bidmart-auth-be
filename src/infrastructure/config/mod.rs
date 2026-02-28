use config::ConfigError;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub _jwt_secret: String,
    pub _jwt_expiration_hours: i64,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        // Try to load .env from project root (where Cargo.toml is)
        let project_root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".env");

        // Try current directory first
        dotenv::dotenv().ok();

        // If .env doesn't exist in current dir, try project root
        if !project_root.exists() {
            let cargo_root = std::env::var("CARGO_MANIFEST_DIR")
                .map(|p| PathBuf::from(p).parent().unwrap().join(".env"))
                .ok();

            if let Some(path) = cargo_root {
                if path.exists() {
                    dotenv::from_path(&path).ok();
                }
            }
        }

        // Read values from environment directly (case-insensitive)
        let server_host = std::env::var("APP_SERVER_HOST")
            .map_err(|_| ConfigError::Message("Missing APP_SERVER_HOST".to_string()))?;

        let server_port = std::env::var("APP_SERVER_PORT")
            .map_err(|_| ConfigError::Message("Missing APP_SERVER_PORT".to_string()))?
            .parse::<u16>()
            .map_err(|_| ConfigError::Message("Invalid SERVER_PORT".to_string()))?;

        let database_url = std::env::var("APP_DATABASE_URL")
            .map_err(|_| ConfigError::Message("Missing APP_DATABASE_URL".to_string()))?;

        let jwt_secret = std::env::var("APP_JWT_SECRET")
            .map_err(|_| ConfigError::Message("Missing APP_JWT_SECRET".to_string()))?;

        let jwt_expiration_hours = std::env::var("APP_JWT_EXPIRATION_HOURS")
            .map_err(|_| ConfigError::Message("Missing APP_JWT_EXPIRATION_HOURS".to_string()))?
            .parse::<i64>()
            .map_err(|_| ConfigError::Message("Invalid JWT_EXPIRATION_HOURS".to_string()))?;

        Ok(AppConfig {
            server_host,
            server_port,
            database_url,
            _jwt_secret: jwt_secret,
            _jwt_expiration_hours: jwt_expiration_hours,
        })
    }
}
