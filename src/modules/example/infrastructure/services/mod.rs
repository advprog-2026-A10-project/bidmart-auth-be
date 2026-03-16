use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;
use scrypt::password_hash::rand_core::OsRng as PasswordSaltRng;
use scrypt::password_hash::SaltString;
use scrypt::{password_hash::PasswordHasher as _, Scrypt};
use sha2::{Digest, Sha256};

use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, PasswordHasher, VerificationEmailSender, VerificationTokenGenerator,
    VerificationTokenHasher,
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

#[derive(Clone)]
pub struct ResendVerificationEmailSender {
    client: Arc<Resend>,
    from_email: String,
    verify_email_url_base: String,
}

impl ResendVerificationEmailSender {
    pub fn new(client: Resend, from_email: String, verify_email_url_base: String) -> Self {
        Self {
            client: Arc::new(client),
            from_email,
            verify_email_url_base,
        }
    }
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
