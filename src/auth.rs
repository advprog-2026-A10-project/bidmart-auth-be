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
    use super::{hash_password, verify_password};

    #[test]
    fn password_hash_and_verify_work() {
        let plain = "supersecret123";
        let hashed = hash_password(plain).expect("hash should be generated");

        assert!(verify_password(plain, &hashed).expect("verification should run"));
        assert!(!verify_password("wrong-password", &hashed).expect("verification should run"));
    }
}
