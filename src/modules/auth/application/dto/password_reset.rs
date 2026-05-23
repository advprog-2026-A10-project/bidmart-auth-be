use serde::Deserialize;
use validator::Validate;

use super::common::MessageResponseDto;

pub const FORGOT_PASSWORD_MESSAGE: &str =
    "If the account exists, a password reset email has been sent.";
pub const RESET_PASSWORD_SUCCESS_MESSAGE: &str = "Password reset successful.";

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ForgotPasswordCommand {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgotPasswordResult {
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ResetPasswordCommand {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetPasswordResult {
    pub message: String,
}

impl From<ForgotPasswordResult> for MessageResponseDto {
    fn from(result: ForgotPasswordResult) -> Self {
        Self {
            message: result.message,
        }
    }
}

impl From<ResetPasswordResult> for MessageResponseDto {
    fn from(result: ResetPasswordResult) -> Self {
        Self {
            message: result.message,
        }
    }
}
