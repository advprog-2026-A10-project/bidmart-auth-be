use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn hash_password(plain_password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(plain_password.as_bytes(), &salt)
        .map_err(|e| AppError::Other(anyhow::anyhow!("password hashing failed: {e}")))?;

    Ok(hashed.to_string())
}

pub fn verify_password(plain_password: &str, password_hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| AppError::Other(anyhow::anyhow!("password hash parsing failed: {e}")))?;

    Ok(Argon2::default()
        .verify_password(plain_password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn issue_jwt(user_id: Uuid, email: &str, config: &Config) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = now + Duration::minutes(config.jwt_expiry_minutes);
    let claims = Claims {
        sub: user_id,
        email: email.to_owned(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Other(anyhow::anyhow!("jwt encode failed: {e}")))
}

pub fn decode_jwt(token: &str, config: &Config) -> Result<Claims, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized("invalid or expired token".to_owned()))
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn validate_email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::BadRequest("invalid email address".to_owned()));
    }

    Ok(email)
}

pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must have at least 8 characters".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        decode_jwt, hash_password, hash_token, issue_jwt, validate_email, validate_password,
        verify_password,
    };
    use crate::config::Config;

    fn test_config(secret: &str) -> Config {
        Config {
            app_host: "127.0.0.1".to_owned(),
            app_port: 8080,
            database_url: "postgres://user:password@localhost/test".to_owned(),
            database_max_connections: 1,
            jwt_secret: secret.to_owned(),
            jwt_expiry_minutes: 30,
            cors_origin: "*".to_owned(),
        }
    }

    #[test]
    fn password_hash_and_verify_work() {
        let plain = "supersecret123";
        let hashed = hash_password(plain).expect("hash should be generated");

        assert!(verify_password(plain, &hashed).expect("verification should run"));
        assert!(!verify_password("wrong-password", &hashed).expect("verification should run"));
    }

    #[test]
    fn verify_password_returns_error_for_invalid_hash() {
        let err = verify_password("whatever", "not-a-valid-password-hash").expect_err("must fail");
        assert!(matches!(err, crate::error::AppError::Other(_)));
    }

    #[test]
    fn jwt_issue_and_decode_roundtrip() {
        let cfg = test_config("01234567890123456789012345678901");
        let user_id = Uuid::new_v4();
        let email = "user@example.com";

        let token = issue_jwt(user_id, email, &cfg).expect("jwt should be issued");
        let claims = decode_jwt(&token, &cfg).expect("jwt should decode");

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, email);
        assert!(claims.exp >= claims.iat);
    }

    #[test]
    fn jwt_decode_fails_with_different_secret() {
        let cfg_sign = test_config("01234567890123456789012345678901");
        let cfg_verify = test_config("abcdefghijklmnopqrstuvwxyz123456");
        let token = issue_jwt(Uuid::new_v4(), "user@example.com", &cfg_sign).expect("jwt");

        let err = decode_jwt(&token, &cfg_verify).expect_err("must fail");
        assert!(matches!(err, crate::error::AppError::Unauthorized(_)));
    }

    #[test]
    fn hash_token_is_deterministic() {
        let first = hash_token("sample-token");
        let second = hash_token("sample-token");
        let third = hash_token("other-token");

        assert_eq!(first, second);
        assert_ne!(first, third);
        assert!(!first.is_empty());
    }

    #[test]
    fn validate_email_normalizes_and_rejects_invalid_input() {
        let normalized = validate_email("  TeSt@Example.COM ").expect("must normalize");
        assert_eq!(normalized, "test@example.com");

        let invalid = validate_email("invalid-email").expect_err("must reject");
        assert!(matches!(invalid, crate::error::AppError::BadRequest(_)));
    }

    #[test]
    fn validate_password_enforces_minimum_length() {
        assert!(validate_password("12345678").is_ok());
        let err = validate_password("123").expect_err("must reject short");
        assert!(matches!(err, crate::error::AppError::BadRequest(_)));
    }
}
