use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub const REGISTER_SUCCESS_MESSAGE: &str = "Registration successful. Please verify your email.";
pub const VERIFY_EMAIL_SUCCESS_MESSAGE: &str = "Email verified.";
pub const RESEND_VERIFICATION_MESSAGE: &str =
    "If the account exists and requires verification, a verification email has been sent.";
pub const FORGOT_PASSWORD_MESSAGE: &str =
    "If the account exists, a password reset email has been sent.";
pub const RESET_PASSWORD_SUCCESS_MESSAGE: &str = "Password reset successful.";

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

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateProfileCommand {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    pub address: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsProfileUserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub address: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsProfileResponseDto {
    pub user: SettingsProfileUserDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateProfileResponseDto {
    pub message: String,
    pub user: SettingsProfileUserDto,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordCommand {
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionDto {
    pub id: Uuid,
    pub device: String,
    pub browser: String,
    pub os: String,
    pub ip: String,
    pub location: String,
    #[serde(rename = "lastActive")]
    pub last_active: String,
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionsResponseDto {
    pub sessions: Vec<SessionDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreferencesDto {
    #[serde(rename = "emailNotifications")]
    pub email_notifications: bool,
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
    #[serde(rename = "marketingEmails")]
    pub marketing_emails: bool,
    #[serde(rename = "securityAlerts")]
    pub security_alerts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotificationPreferencesResponseDto {
    pub preferences: NotificationPreferencesDto,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateNotificationPreferencesCommand {
    pub preferences: NotificationPreferencesDto,
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
    #[serde(rename = "qrCodeUrl")]
    pub qr_code_url: String,
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
    #[serde(rename = "currentPassword", alias = "password")]
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
    #[serde(rename = "mfaEnabled")]
    pub mfa_enabled: bool,
    #[serde(rename = "mfaType")]
    pub mfa_type: Option<String>,
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
