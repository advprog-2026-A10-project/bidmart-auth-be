pub use crate::modules::auth::domain::entities::{AuthenticatedUserContext, IssuedAccessToken};

mod auth;
mod common;
mod login;
mod mfa_setup;
mod notification;
mod password_reset;
mod profile;
mod session;

pub use auth::{
    RegisterCommandError, RegisterRequestCommand, RegisterResponseDto, RegisterUserCommand,
    RegisterUserResult, ResendVerificationCommand, ResendVerificationResult,
    VerifyEmailCommand, VerifyEmailResult, RESEND_VERIFICATION_MESSAGE,
    VERIFY_EMAIL_SUCCESS_MESSAGE,
};
pub use common::MessageResponseDto;
pub use login::{
    AccessTokenResponseDto, AuthTokenResult, AuthenticatedLoginResult, LoginCommand,
    LoginOutcome, LoginResponseDto, SendEmailMfaCommand, SessionContext,
    ValidateSessionResponseDto, VerifyEmailMfaCommand, VerifyTotpMfaCommand,
    LOGOUT_SUCCESS_MESSAGE,
};
pub use mfa_setup::{
    DisableMfaCommand, MfaSettingsDto, SetupEmailMfaCommand, SetupTotpCommand, SetupTotpResult,
    VerifyEmailMfaSetupCommand, VerifyTotpSetupCommand,
};
pub use notification::{
    NotificationPreferencesDto, NotificationPreferencesResponseDto,
    UpdateNotificationPreferencesCommand,
};
pub use password_reset::{
    ForgotPasswordCommand, ForgotPasswordResult, ResetPasswordCommand, ResetPasswordResult,
    FORGOT_PASSWORD_MESSAGE, RESET_PASSWORD_SUCCESS_MESSAGE,
};
pub use profile::{
    ChangePasswordCommand, SettingsProfileResponseDto, SettingsProfileUserDto,
    UpdateProfileCommand, UpdateProfileResponseDto,
};
pub use session::{SessionDto, SessionsResponseDto};
