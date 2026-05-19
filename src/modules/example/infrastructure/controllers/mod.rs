use std::collections::BTreeMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use validator::{Validate, ValidationErrors};

use crate::modules::auth::application::dto::{
    AccessTokenResponseDto, ChangePasswordCommand, DisableMfaCommand, ForgotPasswordCommand,
    LoginCommand, LoginResponseDto, MessageResponseDto, MfaSettingsDto,
    NotificationPreferencesResponseDto, RegisterResponseDto, RegisterUserCommand,
    ResendVerificationCommand, ResetPasswordCommand, SendEmailMfaCommand, SessionsResponseDto,
    SettingsProfileResponseDto, SetupEmailMfaCommand, SetupTotpCommand, SetupTotpResult,
    UpdateNotificationPreferencesCommand, UpdateProfileCommand, UpdateProfileResponseDto,
    VerifyEmailCommand, VerifyEmailMfaCommand, VerifyEmailMfaSetupCommand, VerifyTotpMfaCommand,
    VerifyTotpSetupCommand,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::infrastructure::auth_extractor::AuthenticatedUser;
use crate::modules::auth::infrastructure::AppState;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<BTreeMap<String, Vec<String>>>,
}

pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterUserCommand>, JsonRejection>,
) -> Result<(StatusCode, Json<RegisterResponseDto>), ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .register_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok((StatusCode::CREATED, Json(result.into())))
}

pub async fn verify_email(
    State(state): State<AppState>,
    payload: Result<Json<VerifyEmailCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .verify_email_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub async fn login(
    State(state): State<AppState>,
    payload: Result<Json<LoginCommand>, JsonRejection>,
) -> Result<Json<LoginResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .auth_mfa_use_case
        .login(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub async fn send_email_mfa(
    State(state): State<AppState>,
    payload: Result<Json<SendEmailMfaCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    state
        .auth_mfa_use_case
        .send_email_mfa(command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(MessageResponseDto {
        message: "MFA code sent.".to_string(),
    }))
}

pub async fn verify_email_mfa(
    State(state): State<AppState>,
    payload: Result<Json<VerifyEmailMfaCommand>, JsonRejection>,
) -> Result<Json<AccessTokenResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .verify_email_mfa(command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result.into()))
}

pub async fn verify_totp_mfa(
    State(state): State<AppState>,
    payload: Result<Json<VerifyTotpMfaCommand>, JsonRejection>,
) -> Result<Json<AccessTokenResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .verify_totp_mfa(command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result.into()))
}

pub async fn get_mfa_settings(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<MfaSettingsDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .get_mfa_settings(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn get_profile(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<SettingsProfileResponseDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .get_profile(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn update_profile(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<UpdateProfileCommand>, JsonRejection>,
) -> Result<Json<UpdateProfileResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .update_profile(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn change_password(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<ChangePasswordCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .change_password(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn get_sessions(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<SessionsResponseDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .get_sessions(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    Path(session_id): Path<Uuid>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .revoke_session(auth, session_id)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .revoke_all_sessions(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn logout(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    state
        .auth_mfa_use_case
        .logout(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_notification_preferences(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<NotificationPreferencesResponseDto>, ApiError> {
    let result = state
        .auth_mfa_use_case
        .get_notification_preferences(auth)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn update_notification_preferences(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<UpdateNotificationPreferencesCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    let result = state
        .auth_mfa_use_case
        .update_notification_preferences(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn setup_totp(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<SetupTotpCommand>, JsonRejection>,
) -> Result<Json<SetupTotpResult>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .setup_totp(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(result))
}

pub async fn verify_totp_setup(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<VerifyTotpSetupCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    state
        .auth_mfa_use_case
        .verify_totp_setup(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(MessageResponseDto {
        message: "TOTP MFA enabled.".to_string(),
    }))
}

pub async fn setup_email_mfa(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<SetupEmailMfaCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    state
        .auth_mfa_use_case
        .setup_email_mfa(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(MessageResponseDto {
        message: "MFA code sent.".to_string(),
    }))
}

pub async fn verify_email_mfa_setup(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<VerifyEmailMfaSetupCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    state
        .auth_mfa_use_case
        .verify_email_mfa_setup(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(MessageResponseDto {
        message: "Email MFA enabled.".to_string(),
    }))
}

pub async fn disable_mfa(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
    payload: Result<Json<DisableMfaCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    state
        .auth_mfa_use_case
        .disable_mfa(auth, command)
        .await
        .map_err(ApiError::from_auth_error)?;
    Ok(Json(MessageResponseDto {
        message: "MFA disabled.".to_string(),
    }))
}

pub async fn resend_verification(
    State(state): State<AppState>,
    payload: Result<Json<ResendVerificationCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .resend_verification_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    payload: Result<Json<ForgotPasswordCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .forgot_password_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub async fn reset_password(
    State(state): State<AppState>,
    payload: Result<Json<ResetPasswordCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .reset_password_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub enum ApiError {
    Validation {
        message: String,
        errors: BTreeMap<String, Vec<String>>,
    },
    Message {
        status: StatusCode,
        message: String,
    },
}

impl ApiError {
    fn from_json_rejection(rejection: JsonRejection) -> Self {
        Self::Message {
            status: rejection.status(),
            message: "Invalid JSON payload.".to_string(),
        }
    }

    fn from_validation_errors(errors: ValidationErrors) -> Self {
        let mut field_errors = BTreeMap::new();
        for (field, errors_for_field) in errors.field_errors() {
            let messages = errors_for_field
                .iter()
                .map(|error| {
                    error
                        .message
                        .as_ref()
                        .map(|message| message.to_string())
                        .unwrap_or_else(|| "Invalid value.".to_string())
                })
                .collect::<Vec<_>>();
            field_errors.insert(field.to_string(), messages);
        }

        Self::Validation {
            message: "Validation error".to_string(),
            errors: field_errors,
        }
    }

    pub fn from_auth_error(error: AuthError) -> Self {
        match error {
            AuthError::InvalidName => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("name", "Name is required"),
            },
            AuthError::InvalidEmail => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("email", "Email must be a valid email address"),
            },
            AuthError::WeakPassword => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("password", "Password must be at least 8 characters"),
            },
            AuthError::EmailAlreadyExists => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("email", "Email already exists"),
            },
            AuthError::VerificationTokenExpired => Self::Message {
                status: StatusCode::GONE,
                message: "Verification token expired.".to_string(),
            },
            AuthError::VerificationTokenInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token invalid.".to_string(),
            },
            AuthError::VerificationTokenAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token already used.".to_string(),
            },
            AuthError::VerificationCooldownActive => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification email was sent recently. Please wait before trying again."
                    .to_string(),
            },
            AuthError::PasswordResetTokenExpired => Self::Message {
                status: StatusCode::GONE,
                message: "Password reset token expired.".to_string(),
            },
            AuthError::PasswordResetTokenInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Password reset token invalid.".to_string(),
            },
            AuthError::PasswordResetTokenAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Password reset token already used.".to_string(),
            },
            AuthError::UserAlreadyVerified => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Email is already verified.".to_string(),
            },
            AuthError::UserNotFound => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token invalid.".to_string(),
            },
            AuthError::InvalidCredentials => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Invalid email or password.".to_string(),
            },
            AuthError::EmailNotVerified => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "Email must be verified before login.".to_string(),
            },
            AuthError::UserDisabled => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "User account is disabled.".to_string(),
            },
            AuthError::MfaTicketInvalid | AuthError::TotpSetupInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA ticket invalid.".to_string(),
            },
            AuthError::MfaTicketExpired => Self::Message {
                status: StatusCode::GONE,
                message: "MFA ticket expired.".to_string(),
            },
            AuthError::MfaCodeInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code invalid.".to_string(),
            },
            AuthError::MfaCodeExpired => Self::Message {
                status: StatusCode::GONE,
                message: "MFA code expired.".to_string(),
            },
            AuthError::MfaCodeAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code already used.".to_string(),
            },
            AuthError::MfaCodeCooldownActive => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code was sent recently. Please wait before trying again.".to_string(),
            },
            AuthError::CurrentPasswordRequired => Self::Message {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: "Current password is required.".to_string(),
            },
            AuthError::CurrentPasswordInvalid => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Current password is invalid.".to_string(),
            },
            AuthError::Unauthorized | AuthError::SessionInvalid => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Unauthorized.".to_string(),
            },
            AuthError::SessionNotFound => Self::Message {
                status: StatusCode::NOT_FOUND,
                message: "Session not found.".to_string(),
            },
            AuthError::Forbidden => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "Forbidden.".to_string(),
            },
            AuthError::DependencyFailure(_) => Self::Message {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error.".to_string(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Validation { message, errors } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorEnvelope {
                    message,
                    errors: Some(errors),
                }),
            )
                .into_response(),
            Self::Message { status, message } => (
                status,
                Json(ErrorEnvelope {
                    message,
                    errors: None,
                }),
            )
                .into_response(),
        }
    }
}

fn field_map(field: &str, message: &str) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([(field.to_string(), vec![message.to_string()])])
}
