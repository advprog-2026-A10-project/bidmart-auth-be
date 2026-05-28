use serde::{Deserialize, Serialize};
use validator::Validate;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaSettingsDto {
    #[serde(rename = "mfaEnabled")]
    pub mfa_enabled: bool,
    #[serde(rename = "mfaType")]
    pub mfa_type: Option<String>,
}
