use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use super::common::PublicUserDto;

pub const LOGOUT_SUCCESS_MESSAGE: &str = "Logout successful.";

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginCommand {
    #[validate(email(message = "Email must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Authenticated(AuthenticatedLoginResult),
    MfaRequired {
        mfa_ticket: String,
        mfa_type: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTokenResult {
    pub user_id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub access_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedLoginResult {
    pub user_id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub access_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub device: String,
    pub browser: String,
    pub os: String,
    pub ip: String,
    pub location: String,
}

impl SessionContext {
    pub fn unknown() -> Self {
        Self {
            device: "Unknown device".to_string(),
            browser: "Unknown browser".to_string(),
            os: "Unknown OS".to_string(),
            ip: "Unknown IP".to_string(),
            location: "Unknown location".to_string(),
        }
    }
}

impl Default for SessionContext {
    fn default() -> Self {
        Self::unknown()
    }
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SendEmailMfaCommand {
    #[serde(rename = "ticket", alias = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyEmailMfaCommand {
    #[serde(rename = "ticket", alias = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyTotpMfaCommand {
    #[serde(rename = "ticket", alias = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponseDto {
    pub requires_mfa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PublicUserDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponseDto {
    pub user: PublicUserDto,
    pub access_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateSessionResponseDto {
    pub user_id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub mfa_satisfied: bool,
    pub session_expiry: String,
}

impl From<LoginOutcome> for LoginResponseDto {
    fn from(result: LoginOutcome) -> Self {
        match result {
            LoginOutcome::Authenticated(result) => Self {
                requires_mfa: false,
                user: Some(PublicUserDto {
                    id: result.user_id,
                    name: result.name,
                    email: result.email,
                    email_verified: result.email_verified,
                }),
                access_token: Some(result.access_token),
                ticket: None,
                mfa_type: None,
            },
            LoginOutcome::MfaRequired {
                mfa_ticket,
                mfa_type,
            } => Self {
                requires_mfa: true,
                user: None,
                access_token: None,
                ticket: Some(mfa_ticket),
                mfa_type: Some(mfa_type),
            },
        }
    }
}

impl From<AuthTokenResult> for AccessTokenResponseDto {
    fn from(result: AuthTokenResult) -> Self {
        Self {
            user: PublicUserDto {
                id: result.user_id,
                name: result.name,
                email: result.email,
                email_verified: result.email_verified,
            },
            access_token: result.access_token,
        }
    }
}
