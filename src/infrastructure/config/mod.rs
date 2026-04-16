use base64::Engine;
use config::ConfigError;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub auth_min_password_length: usize,
    pub auth_verification_token_ttl_seconds: i64,
    pub auth_resend_cooldown_seconds: i64,
    pub auth_mfa_ticket_ttl_seconds: i64,
    pub auth_email_mfa_code_ttl_seconds: i64,
    pub auth_email_mfa_cooldown_seconds: i64,
    pub auth_access_token_ttl_seconds: i64,
    pub auth_totp_setup_ttl_seconds: i64,
    pub auth_jwt_secret: String,
    pub resend_api_key: String,
    pub resend_from_email: String,
    pub verify_email_url_base: String,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let project_root = current_dir.join(".env");
        dotenvy::dotenv().ok();

        if !project_root.exists() {
            let cargo_root = std::env::var("CARGO_MANIFEST_DIR").ok().and_then(|path| {
                PathBuf::from(path)
                    .parent()
                    .map(|parent| parent.join(".env"))
            });

            if let Some(path) = cargo_root {
                if path.exists() {
                    dotenvy::from_path(&path).ok();
                }
            }
        }

        Ok(AppConfig {
            server_host: required_env("APP_SERVER_HOST")?,
            server_port: parsed_env("APP_SERVER_PORT")?,
            database_url: required_env("APP_DATABASE_URL")?,
            auth_min_password_length: optional_parsed_env("APP_AUTH_MIN_PASSWORD_LENGTH", 8)?,
            auth_verification_token_ttl_seconds: optional_parsed_env(
                "APP_AUTH_VERIFICATION_TOKEN_TTL_SECONDS",
                30,
            )?,
            auth_resend_cooldown_seconds: optional_parsed_env(
                "APP_AUTH_RESEND_COOLDOWN_SECONDS",
                30,
            )?,
            auth_mfa_ticket_ttl_seconds: optional_parsed_env(
                "APP_AUTH_MFA_TICKET_TTL_SECONDS",
                300,
            )?,
            auth_email_mfa_code_ttl_seconds: optional_parsed_env(
                "APP_AUTH_EMAIL_MFA_CODE_TTL_SECONDS",
                300,
            )?,
            auth_email_mfa_cooldown_seconds: optional_parsed_env(
                "APP_AUTH_EMAIL_MFA_COOLDOWN_SECONDS",
                30,
            )?,
            auth_access_token_ttl_seconds: optional_parsed_env(
                "APP_AUTH_ACCESS_TOKEN_TTL_SECONDS",
                3600,
            )?,
            auth_totp_setup_ttl_seconds: optional_parsed_env(
                "APP_AUTH_TOTP_SETUP_TTL_SECONDS",
                600,
            )?,
            auth_jwt_secret: required_jwt_secret("APP_AUTH_JWT_SECRET")?,
            resend_api_key: required_env("APP_RESEND_API_KEY")?,
            resend_from_email: required_env("APP_RESEND_FROM_EMAIL")?,
            verify_email_url_base: required_env("APP_VERIFY_EMAIL_URL_BASE")?,
        })
    }
}

fn required_jwt_secret(key: &str) -> Result<String, ConfigError> {
    let value = required_env(key)?;
    let key_material_len = base64::engine::general_purpose::STANDARD
        .decode(&value)
        .map(|bytes| bytes.len())
        .unwrap_or_else(|_| value.len());
    if key_material_len < 32 {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: use at least 32 bytes of key material or standard base64-encoded bytes"
        )));
    }
    Ok(value)
}

fn required_env(key: &str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::Message(format!("Missing {key}")))
}

fn parsed_env<T>(key: &str) -> Result<T, ConfigError>
where
    T: FromStr,
{
    required_env(key)?
        .parse::<T>()
        .map_err(|_| ConfigError::Message(format!("Invalid {key}")))
}

fn optional_parsed_env<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
{
    match std::env::var(key) {
        Ok(value) => value
            .parse::<T>()
            .map_err(|_| ConfigError::Message(format!("Invalid {key}"))),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(ConfigError::Message(format!("Invalid {key}"))),
    }
}
