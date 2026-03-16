use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub const REGISTER_SUCCESS_MESSAGE: &str = "Registration successful. Please verify your email.";
pub const VERIFY_EMAIL_SUCCESS_MESSAGE: &str = "Email verified.";
pub const RESEND_VERIFICATION_MESSAGE: &str =
    "If the account exists and requires verification, a verification email has been sent.";

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterUserCommand {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(email(message = "Email must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserResult {
    pub user_id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyEmailCommand {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEmailResult {
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ResendVerificationCommand {
    #[validate(email(message = "Email must be a valid email address"))]
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendVerificationResult {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicUserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterResponseDto {
    pub user: PublicUserDto,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageResponseDto {
    pub message: String,
}

impl From<RegisterUserResult> for RegisterResponseDto {
    fn from(result: RegisterUserResult) -> Self {
        Self {
            user: PublicUserDto {
                id: result.user_id,
                name: result.name,
                email: result.email,
                email_verified: result.email_verified,
            },
            message: REGISTER_SUCCESS_MESSAGE.to_string(),
        }
    }
}

impl From<VerifyEmailResult> for MessageResponseDto {
    fn from(result: VerifyEmailResult) -> Self {
        Self {
            message: result.message,
        }
    }
}

impl From<ResendVerificationResult> for MessageResponseDto {
    fn from(result: ResendVerificationResult) -> Self {
        Self {
            message: result.message,
        }
    }
}
