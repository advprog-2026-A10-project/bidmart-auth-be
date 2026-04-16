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

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginCommand {
    #[validate(email(message = "Email must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Authenticated {
        access_token: String,
    },
    MfaRequired {
        mfa_ticket: String,
        methods: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTokenResult {
    pub access_token: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SendEmailMfaCommand {
    #[serde(rename = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyEmailMfaCommand {
    #[serde(rename = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyTotpMfaCommand {
    #[serde(rename = "mfaTicket")]
    #[validate(length(min = 1, message = "MFA ticket is required"))]
    pub mfa_ticket: String,
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SetupTotpCommand {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupTotpResult {
    #[serde(rename = "setupTicket")]
    pub setup_ticket: String,
    pub secret: String,
    #[serde(rename = "otpauthUrl")]
    pub otpauth_url: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyTotpSetupCommand {
    #[serde(rename = "setupTicket")]
    #[validate(length(min = 1, message = "Setup ticket is required"))]
    pub setup_ticket: String,
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SetupEmailMfaCommand {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyEmailMfaSetupCommand {
    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct DisableMfaCommand {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUserContext {
    pub user_id: Uuid,
    pub mfa_satisfied: bool,
    pub session_jti_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaSettingsDto {
    #[serde(rename = "emailEnabled")]
    pub email_enabled: bool,
    #[serde(rename = "totpEnabled")]
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAccessToken {
    pub token: String,
    pub jti: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponseDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponseDto {
    pub access_token: String,
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

impl From<LoginOutcome> for LoginResponseDto {
    fn from(result: LoginOutcome) -> Self {
        match result {
            LoginOutcome::Authenticated { access_token } => Self {
                access_token: Some(access_token),
                mfa_ticket: None,
                methods: None,
            },
            LoginOutcome::MfaRequired {
                mfa_ticket,
                methods,
            } => Self {
                access_token: None,
                mfa_ticket: Some(mfa_ticket),
                methods: Some(methods),
            },
        }
    }
}

impl From<AuthTokenResult> for AccessTokenResponseDto {
    fn from(result: AuthTokenResult) -> Self {
        Self {
            access_token: result.access_token,
        }
    }
}
