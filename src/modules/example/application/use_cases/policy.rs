use chrono::Duration;

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub min_password_length: usize,
    pub verification_token_ttl: Duration,
    pub resend_cooldown: Duration,
    pub password_reset_token_ttl: Duration,
    pub password_reset_cooldown: Duration,
    pub mfa_ticket_ttl: Duration,
    pub email_mfa_code_ttl: Duration,
    pub email_mfa_cooldown: Duration,
    pub access_token_ttl: Duration,
    pub totp_setup_ttl: Duration,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            verification_token_ttl: Duration::seconds(30),
            resend_cooldown: Duration::seconds(30),
            password_reset_token_ttl: Duration::minutes(15),
            password_reset_cooldown: Duration::seconds(30),
            mfa_ticket_ttl: Duration::minutes(5),
            email_mfa_code_ttl: Duration::minutes(5),
            email_mfa_cooldown: Duration::seconds(30),
            access_token_ttl: Duration::hours(1),
            totp_setup_ttl: Duration::minutes(10),
        }
    }
}
