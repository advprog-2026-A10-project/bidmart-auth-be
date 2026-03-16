use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserCommand {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserResult {
    pub user_id: Uuid,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEmailCommand {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEmailResult {
    pub user_id: Uuid,
    pub email_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendVerificationCommand {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendVerificationResult {
    pub user_id: Uuid,
    pub email: String,
}
