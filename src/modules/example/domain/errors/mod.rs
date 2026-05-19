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
    #[error("password reset token invalid")]
    PasswordResetTokenInvalid,
    #[error("password reset token expired")]
    PasswordResetTokenExpired,
    #[error("password reset token already used")]
    PasswordResetTokenAlreadyUsed,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("email not verified")]
    EmailNotVerified,
    #[error("user disabled")]
    UserDisabled,
    #[error("mfa ticket invalid")]
    MfaTicketInvalid,
    #[error("mfa ticket expired")]
    MfaTicketExpired,
    #[error("mfa code invalid")]
    MfaCodeInvalid,
    #[error("mfa code expired")]
    MfaCodeExpired,
    #[error("mfa code already used")]
    MfaCodeAlreadyUsed,
    #[error("mfa code cooldown active")]
    MfaCodeCooldownActive,
    #[error("current password required")]
    CurrentPasswordRequired,
    #[error("current password invalid")]
    CurrentPasswordInvalid,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("too many attempts")]
    TooManyAttempts,
    #[error("totp setup invalid")]
    TotpSetupInvalid,
    #[error("session invalid")]
    SessionInvalid,
    #[error("session not found")]
    SessionNotFound,
    #[error("dependency failure: {0}")]
    DependencyFailure(String),
}
