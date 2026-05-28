use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use super::common::{MessageResponseDto, PublicUserDto};

pub const REGISTER_SUCCESS_MESSAGE: &str = "Registration successful. Please verify your email.";
pub const VERIFY_EMAIL_SUCCESS_MESSAGE: &str = "Email verified.";
pub const RESEND_VERIFICATION_MESSAGE: &str =
    "If the account exists and requires verification, a verification email has been sent.";

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterRequestCommand {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    pub name: Option<String>,
    #[validate(email(message = "Email must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    #[serde(rename = "confirmPassword")]
    pub confirm_password: Option<String>,
}

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
    pub user_id: Uuid,
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
pub struct RegisterResponseDto {
    pub user: PublicUserDto,
    pub message: String,
}

pub enum RegisterCommandError {
    ConfirmPasswordRequired,
    PasswordsDoNotMatch,
    NameRequired,
    FirstNameRequired,
}

impl RegisterRequestCommand {
    pub fn into_use_case_command(self) -> Result<RegisterUserCommand, RegisterCommandError> {
        let email = self.email.trim().to_string();
        let password = self.password;

        let first_name = self
            .first_name
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let last_name = self
            .last_name
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        if let Some(first_name) = first_name {
            let confirm_password = self
                .confirm_password
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or(RegisterCommandError::ConfirmPasswordRequired)?;

            if confirm_password != password {
                return Err(RegisterCommandError::PasswordsDoNotMatch);
            }

            let name = match last_name {
                Some(last_name) => format!("{first_name} {last_name}"),
                None => first_name,
            };
            return Ok(RegisterUserCommand {
                name,
                email,
                password,
            });
        }

        let legacy_name = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let legacy_name = match legacy_name {
            Some(name) => name,
            None if self.name.is_some() => return Err(RegisterCommandError::NameRequired),
            None => return Err(RegisterCommandError::FirstNameRequired),
        };

        if let Some(confirm_password) = self
            .confirm_password
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            if confirm_password != password {
                return Err(RegisterCommandError::PasswordsDoNotMatch);
            }
        }

        Ok(RegisterUserCommand {
            name: legacy_name,
            email,
            password,
        })
    }
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
