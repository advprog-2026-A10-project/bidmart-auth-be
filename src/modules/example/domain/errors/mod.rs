use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("invalid name")]
    InvalidName,
    #[error("invalid email")]
    InvalidEmail,
    #[error("weak password")]
    WeakPassword,
    #[error("email already exists")]
    EmailAlreadyExists,
    #[error("user not found")]
    UserNotFound,
    #[error("user already verified")]
    UserAlreadyVerified,
    #[error("verification token invalid")]
    VerificationTokenInvalid,
    #[error("verification token expired")]
    VerificationTokenExpired,
    #[error("verification token already used")]
    VerificationTokenAlreadyUsed,
    #[error("verification cooldown active")]
    VerificationCooldownActive,
    #[error("dependency failure: {0}")]
    DependencyFailure(String),
}
