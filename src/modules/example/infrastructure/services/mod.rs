use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use rand::RngCore;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;
use scrypt::password_hash::SaltString;
use scrypt::password_hash::{
    rand_core::OsRng as PasswordSaltRng, PasswordHash, PasswordVerifier as _,
};
use scrypt::{password_hash::PasswordHasher as _, Scrypt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};
use uuid::Uuid;

use crate::modules::auth::application::dto::{AuthenticatedUserContext, IssuedAccessToken};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    AuthAttemptLimiter, Clock, JwtService, MfaEmailSender, PasswordHasher,
    PasswordResetEmailSender, PasswordVerifier, TotpService, VerificationEmailSender,
    VerificationTokenGenerator, VerificationTokenHasher,
};

#[derive(Debug, Default)]
pub struct ScryptPasswordHasher;

impl PasswordHasher for ScryptPasswordHasher {
    fn hash(&self, raw_password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut PasswordSaltRng);
        Scrypt
            .hash_password(raw_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AuthError::DependencyFailure("failed to hash password".to_string()))
    }
}

impl PasswordVerifier for ScryptPasswordHasher {
    fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError> {
        let parsed_hash =
            PasswordHash::new(password_hash).map_err(|_| AuthError::InvalidCredentials)?;
        Ok(Scrypt
            .verify_password(raw_password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

#[derive(Debug, Default)]
pub struct RandomVerificationTokenGenerator;

impl VerificationTokenGenerator for RandomVerificationTokenGenerator {
    fn generate(&self) -> Result<String, AuthError> {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[derive(Debug, Default)]
pub struct Sha256VerificationTokenHasher;

impl VerificationTokenHasher for Sha256VerificationTokenHasher {
    fn hash(&self, raw_token: &str) -> Result<String, AuthError> {
        let digest = Sha256::digest(raw_token.as_bytes());
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug)]
pub struct InMemoryAuthAttemptLimiter {
    max_failures: usize,
    window: Duration,
    failures_by_key: Mutex<HashMap<u64, VecDeque<DateTime<Utc>>>>,
}

impl InMemoryAuthAttemptLimiter {
    pub fn new(max_failures: usize, window: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            window,
            failures_by_key: Mutex::new(HashMap::new()),
        }
    }

    fn hashed_key(key: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn retain_window(failures: &mut VecDeque<DateTime<Utc>>, cutoff: DateTime<Utc>) {
        while failures
            .front()
            .map(|timestamp| *timestamp < cutoff)
            .unwrap_or(false)
        {
            failures.pop_front();
        }
    }
}

impl AuthAttemptLimiter for InMemoryAuthAttemptLimiter {
    fn check(&self, key: &str, now: DateTime<Utc>) -> Result<(), AuthError> {
        let hashed_key = Self::hashed_key(key);
        let mut failures_by_key = self
            .failures_by_key
            .lock()
            .expect("auth attempt limiter lock poisoned");
        let failures = failures_by_key.entry(hashed_key).or_default();
        Self::retain_window(failures, now - self.window);
        if failures.len() >= self.max_failures {
            return Err(AuthError::TooManyAttempts);
        }
        Ok(())
    }

    fn record_failure(&self, key: &str, now: DateTime<Utc>) {
        let hashed_key = Self::hashed_key(key);
        let mut failures_by_key = self
            .failures_by_key
            .lock()
            .expect("auth attempt limiter lock poisoned");
        let failures = failures_by_key.entry(hashed_key).or_default();
        Self::retain_window(failures, now - self.window);
        failures.push_back(now);
    }

    fn record_success(&self, key: &str) {
        let hashed_key = Self::hashed_key(key);
        self.failures_by_key
            .lock()
            .expect("auth attempt limiter lock poisoned")
            .remove(&hashed_key);
    }
}

#[derive(Clone)]
pub struct ResendVerificationEmailSender {
    client: Arc<Resend>,
    from_email: String,
    verify_email_url_base: String,
    password_reset_url_base: String,
}

impl ResendVerificationEmailSender {
    pub fn new(
        client: Resend,
        from_email: String,
        verify_email_url_base: String,
        password_reset_url_base: String,
    ) -> Self {
        Self {
            client: Arc::new(client),
            from_email,
            verify_email_url_base,
            password_reset_url_base,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LoggedEmailSender {
    verify_email_url_base: String,
    password_reset_url_base: String,
}

impl LoggedEmailSender {
    pub fn new(verify_email_url_base: String, password_reset_url_base: String) -> Self {
        Self {
            verify_email_url_base,
            password_reset_url_base,
        }
    }
}

#[derive(Clone)]
pub enum BidMartEmailSender {
    Resend(ResendVerificationEmailSender),
    Log(LoggedEmailSender),
}

#[async_trait]
impl VerificationEmailSender for ResendVerificationEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        let verification_link = format!("{}{}", self.verify_email_url_base, raw_token);
        let html = format!(
            "<p>Verify your BidMart email address by opening this link:</p><p><a href=\"{verification_link}\">{verification_link}</a></p>"
        );
        let text =
            format!("Verify your BidMart email address by opening this link: {verification_link}");

        let email = CreateEmailBaseOptions::new(
            self.from_email.clone(),
            vec![to_email.to_string()],
            "Verify your BidMart email",
        )
        .with_html(&html)
        .with_text(&text);

        self.client.emails.send(email).await.map_err(|_| {
            AuthError::DependencyFailure("failed to send verification email".to_string())
        })?;

        Ok(())
    }
}

#[async_trait]
impl VerificationEmailSender for LoggedEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        let verification_link = format!("{}{}", self.verify_email_url_base, raw_token);
        tracing::info!(
            target: "bidmart_auth_be::email",
            email_type = "verification",
            to_email,
            verification_link,
            "Local email delivery mode logged a verification link"
        );
        Ok(())
    }
}

#[async_trait]
impl MfaEmailSender for ResendVerificationEmailSender {
    async fn send_mfa_code(&self, to_email: &str, raw_code: &str) -> Result<(), AuthError> {
        let html = format!("<p>Your BidMart MFA code is:</p><p><strong>{raw_code}</strong></p>");
        let text = format!("Your BidMart MFA code is: {raw_code}");

        let email = CreateEmailBaseOptions::new(
            self.from_email.clone(),
            vec![to_email.to_string()],
            "Your BidMart MFA code",
        )
        .with_html(&html)
        .with_text(&text);

        self.client
            .emails
            .send(email)
            .await
            .map_err(|_| AuthError::DependencyFailure("failed to send mfa email".to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl MfaEmailSender for LoggedEmailSender {
    async fn send_mfa_code(&self, to_email: &str, raw_code: &str) -> Result<(), AuthError> {
        tracing::info!(
            target: "bidmart_auth_be::email",
            email_type = "mfa",
            to_email,
            raw_code,
            "Local email delivery mode logged an MFA code"
        );
        Ok(())
    }
}

#[async_trait]
impl PasswordResetEmailSender for ResendVerificationEmailSender {
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        let reset_link = format!("{}{}", self.password_reset_url_base, raw_token);
        let html = format!(
            "<p>Reset your BidMart password by opening this link:</p><p><a href=\"{reset_link}\">{reset_link}</a></p>"
        );
        let text = format!("Reset your BidMart password by opening this link: {reset_link}");

        let email = CreateEmailBaseOptions::new(
            self.from_email.clone(),
            vec![to_email.to_string()],
            "Reset your BidMart password",
        )
        .with_html(&html)
        .with_text(&text);

        self.client.emails.send(email).await.map_err(|_| {
            AuthError::DependencyFailure("failed to send password reset email".to_string())
        })?;

        Ok(())
    }
}

#[async_trait]
impl PasswordResetEmailSender for LoggedEmailSender {
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        let reset_link = format!("{}{}", self.password_reset_url_base, raw_token);
        tracing::info!(
            target: "bidmart_auth_be::email",
            email_type = "password_reset",
            to_email,
            reset_link,
            "Local email delivery mode logged a password reset link"
        );
        Ok(())
    }
}

#[async_trait]
impl VerificationEmailSender for BidMartEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        match self {
            Self::Resend(sender) => sender.send_verification_email(to_email, raw_token).await,
            Self::Log(sender) => sender.send_verification_email(to_email, raw_token).await,
        }
    }
}

#[async_trait]
impl MfaEmailSender for BidMartEmailSender {
    async fn send_mfa_code(&self, to_email: &str, raw_code: &str) -> Result<(), AuthError> {
        match self {
            Self::Resend(sender) => sender.send_mfa_code(to_email, raw_code).await,
            Self::Log(sender) => sender.send_mfa_code(to_email, raw_code).await,
        }
    }
}

#[async_trait]
impl PasswordResetEmailSender for BidMartEmailSender {
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        match self {
            Self::Resend(sender) => sender.send_password_reset_email(to_email, raw_token).await,
            Self::Log(sender) => sender.send_password_reset_email(to_email, raw_token).await,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    iat: usize,
    jti: String,
    mfa_satisfied: bool,
    scope: String,
}

#[derive(Clone)]
pub struct Hs256JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    token_ttl_seconds: i64,
}

impl Hs256JwtService {
    pub fn new(secret: &str, token_ttl_seconds: i64) -> Self {
        let key_material = base64::engine::general_purpose::STANDARD
            .decode(secret)
            .unwrap_or_else(|_| secret.as_bytes().to_vec());
        Self {
            encoding_key: EncodingKey::from_secret(&key_material),
            decoding_key: DecodingKey::from_secret(&key_material),
            token_ttl_seconds,
        }
    }
}

impl JwtService for Hs256JwtService {
    fn issue_access_token(
        &self,
        user_id: Uuid,
        mfa_satisfied: bool,
        now: DateTime<Utc>,
    ) -> Result<IssuedAccessToken, AuthError> {
        let expires_at = now + chrono::Duration::seconds(self.token_ttl_seconds);
        let jti = Uuid::new_v4().to_string();
        let claims = JwtClaims {
            sub: user_id.to_string(),
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: jti.clone(),
            mfa_satisfied,
            scope: "access".to_string(),
        };
        let token =
            encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key).map_err(|_| {
                AuthError::DependencyFailure("failed to issue access token".to_string())
            })?;
        Ok(IssuedAccessToken {
            token,
            jti,
            expires_at,
        })
    }

    fn verify_access_token(
        &self,
        token: &str,
        _now: DateTime<Utc>,
    ) -> Result<AuthenticatedUserContext, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("iat".to_string());
        validation.required_spec_claims.insert("sub".to_string());
        let decoded = decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|_| AuthError::Unauthorized)?;
        if decoded.claims.scope != "access" {
            return Err(AuthError::Unauthorized);
        }
        let user_id = Uuid::parse_str(&decoded.claims.sub).map_err(|_| AuthError::Unauthorized)?;
        Ok(AuthenticatedUserContext {
            user_id,
            mfa_satisfied: decoded.claims.mfa_satisfied,
            session_jti_hash: Some(self.jti_hash(&decoded.claims.jti)?),
        })
    }

    fn jti_hash(&self, jti: &str) -> Result<String, AuthError> {
        Sha256VerificationTokenHasher.hash(jti)
    }
}

#[derive(Debug, Default)]
pub struct TotpRsService;

impl TotpService for TotpRsService {
    fn generate_secret(&self) -> Result<String, AuthError> {
        let mut bytes = [0_u8; 20];
        OsRng.fill_bytes(&mut bytes);
        Ok(Secret::Raw(bytes.to_vec()).to_encoded().to_string())
    }

    fn otpauth_url(&self, email: &str, secret: &str) -> Result<String, AuthError> {
        Ok(format!(
            "otpauth://totp/BidMart:{email}?secret={secret}&issuer=BidMart"
        ))
    }

    fn verify_code(&self, secret: &str, code: &str, now: DateTime<Utc>) -> Result<bool, AuthError> {
        let totp = totp_from_secret(secret)?;
        Ok(totp.check(code, now.timestamp() as u64))
    }
}

fn totp_from_secret(secret: &str) -> Result<TOTP, AuthError> {
    let decoded = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|_| AuthError::DependencyFailure("invalid totp secret".to_string()))?;
    TOTP::new(TotpAlgorithm::SHA1, 6, 1, 30, decoded)
        .map_err(|_| AuthError::DependencyFailure("failed to create totp".to_string()))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{AuthAttemptLimiter, InMemoryAuthAttemptLimiter};
    use crate::modules::auth::domain::errors::AuthError;

    #[test]
    fn in_memory_attempt_limiter_blocks_until_window_expires_and_resets_on_success() {
        let limiter = InMemoryAuthAttemptLimiter::new(2, Duration::seconds(30));
        let now = Utc.with_ymd_and_hms(2026, 5, 19, 0, 0, 0).unwrap();

        assert_eq!(limiter.check("login:user@example.com", now), Ok(()));
        limiter.record_failure("login:user@example.com", now);
        limiter.record_failure("login:user@example.com", now + Duration::seconds(1));

        assert_eq!(
            limiter.check("login:user@example.com", now + Duration::seconds(2)),
            Err(AuthError::TooManyAttempts)
        );

        assert_eq!(
            limiter.check("login:user@example.com", now + Duration::seconds(31)),
            Ok(())
        );
        limiter.record_failure("login:user@example.com", now + Duration::seconds(31));
        limiter.record_success("login:user@example.com");

        assert_eq!(
            limiter.check("login:user@example.com", now + Duration::seconds(32)),
            Ok(())
        );
    }
}
