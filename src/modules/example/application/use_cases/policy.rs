use chrono::Duration;

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub min_password_length: usize,
    pub verification_token_ttl: Duration,
    pub resend_cooldown: Duration,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            verification_token_ttl: Duration::minutes(15),
            resend_cooldown: Duration::seconds(30),
        }
    }
}
