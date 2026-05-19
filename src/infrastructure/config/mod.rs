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
    pub auth_password_reset_token_ttl_seconds: i64,
    pub auth_password_reset_cooldown_seconds: i64,
    pub auth_mfa_ticket_ttl_seconds: i64,
    pub auth_email_mfa_code_ttl_seconds: i64,
    pub auth_email_mfa_cooldown_seconds: i64,
    pub auth_access_token_ttl_seconds: i64,
    pub auth_totp_setup_ttl_seconds: i64,
    pub auth_jwt_secret: String,
    pub resend_api_key: String,
    pub resend_from_email: String,
    pub verify_email_url_base: String,
    pub password_reset_url_base: String,
    pub cors_allowed_origins: Vec<String>,
    pub auth_session_cookie_name: String,
    pub auth_session_cookie_secure: bool,
    pub auth_session_cookie_same_site: String,
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

        validate_email_configuration()?;

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
            auth_password_reset_token_ttl_seconds: optional_parsed_env(
                "APP_AUTH_PASSWORD_RESET_TOKEN_TTL_SECONDS",
                30,
            )?,
            auth_password_reset_cooldown_seconds: optional_parsed_env(
                "APP_AUTH_PASSWORD_RESET_COOLDOWN_SECONDS",
                30,
            )?,
            auth_mfa_ticket_ttl_seconds: optional_parsed_env(
                "APP_AUTH_MFA_TICKET_TTL_SECONDS",
                300,
            )?,
            auth_email_mfa_code_ttl_seconds: optional_parsed_env(
                "APP_AUTH_EMAIL_MFA_CODE_TTL_SECONDS",
                30,
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
            verify_email_url_base: required_url_base("APP_VERIFY_EMAIL_URL_BASE")?,
            password_reset_url_base: required_url_base("APP_PASSWORD_RESET_URL_BASE")?,
            cors_allowed_origins: cors_allowed_origins("APP_CORS_ALLOWED_ORIGINS")?,
            auth_session_cookie_name: optional_env("APP_AUTH_SESSION_COOKIE_NAME", "auth_session"),
            auth_session_cookie_secure: optional_parsed_env(
                "APP_AUTH_SESSION_COOKIE_SECURE",
                false,
            )?,
            auth_session_cookie_same_site: optional_env("APP_AUTH_SESSION_COOKIE_SAME_SITE", "Lax"),
        })
    }
}

fn required_url_base(key: &str) -> Result<String, ConfigError> {
    let value = required_env(key)?;
    validate_absolute_http_url_base(key, &value)?;
    Ok(value)
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

fn validate_email_configuration() -> Result<(), ConfigError> {
    let delivery_mode = optional_env("APP_EMAIL_DELIVERY_MODE", "resend");
    match delivery_mode.trim().to_ascii_lowercase().as_str() {
        "resend" => {}
        "log" if is_production_environment() => {
            return Err(ConfigError::Message(
                "Invalid APP_EMAIL_DELIVERY_MODE: production cannot use log email delivery"
                    .to_string(),
            ));
        }
        "log" => {}
        _ => {
            return Err(ConfigError::Message(
                "Invalid APP_EMAIL_DELIVERY_MODE: expected 'resend' or 'log'".to_string(),
            ));
        }
    }

    let api_key = required_env("APP_RESEND_API_KEY")?;
    validate_resend_api_key("APP_RESEND_API_KEY", &api_key)?;
    let from_email = required_env("APP_RESEND_FROM_EMAIL")?;
    validate_from_email("APP_RESEND_FROM_EMAIL", &from_email)?;
    Ok(())
}

fn is_production_environment() -> bool {
    ["APP_ENV", "RUST_ENV", "ENVIRONMENT", "NODE_ENV"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .any(|value| value.trim().eq_ignore_ascii_case("production"))
}

fn validate_resend_api_key(key: &str, value: &str) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !trimmed.starts_with("re_")
        || trimmed.len() < 12
        || lower.contains("your")
        || lower.contains("placeholder")
        || lower.contains("xxx")
        || lower.contains("test")
    {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: configure a real Resend API key through the environment"
        )));
    }

    Ok(())
}

fn validate_from_email(key: &str, value: &str) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    let address = trimmed
        .rsplit_once('<')
        .and_then(|(_, rest)| rest.strip_suffix('>'))
        .unwrap_or(trimmed)
        .trim();
    let lower = address.to_ascii_lowercase();

    if !address.contains('@')
        || lower.contains("example.")
        || lower.contains("localhost")
        || lower.ends_with("@gmail.com")
        || lower.ends_with("@yahoo.com")
        || lower.ends_with("@outlook.com")
    {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: use a verified custom-domain sender address"
        )));
    }

    Ok(())
}

fn parsed_env<T>(key: &str) -> Result<T, ConfigError>
where
    T: FromStr,
{
    required_env(key)?
        .parse::<T>()
        .map_err(|_| ConfigError::Message(format!("Invalid {key}")))
}

fn optional_env(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
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

fn validate_absolute_http_url_base(key: &str, value: &str) -> Result<(), ConfigError> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| {
            ConfigError::Message(format!("Invalid {key}: must be an absolute http(s) URL"))
        })?;

    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: must include a host"
        )));
    }

    Ok(())
}

fn cors_allowed_origins(key: &str) -> Result<Vec<String>, ConfigError> {
    let value = std::env::var(key)
        .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string());
    parse_cors_allowed_origins_value(key, &value)
}

fn parse_cors_allowed_origins_value(key: &str, value: &str) -> Result<Vec<String>, ConfigError> {
    let origins = value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| validate_cors_origin(key, origin).map(|()| origin.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    if origins.is_empty() {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: configure at least one origin"
        )));
    }

    Ok(origins)
}

fn validate_cors_origin(key: &str, value: &str) -> Result<(), ConfigError> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| {
            ConfigError::Message(format!(
                "Invalid {key}: origins must be absolute http(s) URLs"
            ))
        })?;

    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
    {
        return Err(ConfigError::Message(format!(
            "Invalid {key}: origins must not include paths, queries, fragments, or credentials"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_cors_allowed_origins_value, validate_absolute_http_url_base, validate_cors_origin,
        validate_email_configuration,
    };
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn absolute_http_url_base_validation_accepts_http_and_https() {
        assert!(validate_absolute_http_url_base(
            "APP_VERIFY_EMAIL_URL_BASE",
            "https://sso.bidmart.com/verify-email?token="
        )
        .is_ok());
        assert!(validate_absolute_http_url_base(
            "APP_PASSWORD_RESET_URL_BASE",
            "http://localhost:5173/reset-password?token="
        )
        .is_ok());
    }

    #[test]
    fn absolute_http_url_base_validation_rejects_relative_or_non_http_urls() {
        assert!(validate_absolute_http_url_base(
            "APP_VERIFY_EMAIL_URL_BASE",
            "/verify-email?token="
        )
        .is_err());
        assert!(validate_absolute_http_url_base(
            "APP_PASSWORD_RESET_URL_BASE",
            "javascript:alert(1)"
        )
        .is_err());
        assert!(validate_absolute_http_url_base(
            "APP_PASSWORD_RESET_URL_BASE",
            "https:///missing-host"
        )
        .is_err());
    }

    #[test]
    fn cors_origin_validation_accepts_origin_list_without_paths() {
        let origins = parse_cors_allowed_origins_value(
            "APP_CORS_ALLOWED_ORIGINS",
            "https://bidmart.example,http://localhost:5173",
        )
        .expect("valid origins");
        assert_eq!(
            origins,
            vec![
                "https://bidmart.example".to_string(),
                "http://localhost:5173".to_string()
            ]
        );
    }

    #[test]
    fn cors_origin_validation_rejects_paths_and_credentials() {
        assert!(
            validate_cors_origin("APP_CORS_ALLOWED_ORIGINS", "https://bidmart.example/app")
                .is_err()
        );
        assert!(
            validate_cors_origin("APP_CORS_ALLOWED_ORIGINS", "https://user@bidmart.example")
                .is_err()
        );
    }
    #[test]
    fn production_rejects_log_email_delivery() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("APP_EMAIL_DELIVERY_MODE", "log");

        let result = validate_email_configuration();

        std::env::remove_var("APP_ENV");
        std::env::remove_var("APP_EMAIL_DELIVERY_MODE");
        assert!(result.is_err());
    }

    #[test]
    fn production_resend_rejects_missing_or_placeholder_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("APP_EMAIL_DELIVERY_MODE", "resend");
        std::env::remove_var("APP_RESEND_API_KEY");
        std::env::set_var(
            "APP_RESEND_FROM_EMAIL",
            "BidMart <no-reply@updates.bidmart.com>",
        );

        let missing = validate_email_configuration();

        std::env::set_var("APP_RESEND_API_KEY", "re_your_api_key");
        let placeholder = validate_email_configuration();

        std::env::remove_var("APP_ENV");
        std::env::remove_var("APP_EMAIL_DELIVERY_MODE");
        std::env::remove_var("APP_RESEND_API_KEY");
        std::env::remove_var("APP_RESEND_FROM_EMAIL");
        assert!(missing.is_err());
        assert!(placeholder.is_err());
    }

    #[test]
    fn invalid_email_delivery_mode_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("APP_EMAIL_DELIVERY_MODE", "stdout");

        let result = validate_email_configuration();

        std::env::remove_var("APP_EMAIL_DELIVERY_MODE");
        assert!(result.is_err());
    }

    #[test]
    fn resend_mode_accepts_configured_key_and_custom_domain_sender() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("APP_ENV", "development");
        std::env::set_var("APP_EMAIL_DELIVERY_MODE", "resend");
        std::env::set_var("APP_RESEND_API_KEY", "re_abcdefghijklmnopqrstuvwxyz");
        std::env::set_var(
            "APP_RESEND_FROM_EMAIL",
            "BidMart <no-reply@updates.bidmart.com>",
        );

        let result = validate_email_configuration();

        std::env::remove_var("APP_ENV");
        std::env::remove_var("APP_EMAIL_DELIVERY_MODE");
        std::env::remove_var("APP_RESEND_API_KEY");
        std::env::remove_var("APP_RESEND_FROM_EMAIL");
        assert!(result.is_ok());
    }

    #[test]
    fn resend_mode_rejects_public_mailbox_sender() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("APP_EMAIL_DELIVERY_MODE", "resend");
        std::env::set_var("APP_RESEND_API_KEY", "re_abcdefghijklmnopqrstuvwxyz");
        std::env::set_var("APP_RESEND_FROM_EMAIL", "BidMart <bidmart@gmail.com>");

        let result = validate_email_configuration();

        std::env::remove_var("APP_EMAIL_DELIVERY_MODE");
        std::env::remove_var("APP_RESEND_API_KEY");
        std::env::remove_var("APP_RESEND_FROM_EMAIL");
        assert!(result.is_err());
    }
}
