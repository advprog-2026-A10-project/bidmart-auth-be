use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;
use validator::Validate;

use crate::modules::auth::application::dto::{
    ChangePasswordCommand, DisableMfaCommand, MessageResponseDto, MfaSettingsDto,
    NotificationPreferencesResponseDto, SessionsResponseDto, SettingsProfileResponseDto,
    SetupEmailMfaCommand, SetupTotpCommand, SetupTotpResult, UpdateNotificationPreferencesCommand,
    UpdateProfileCommand, UpdateProfileResponseDto, VerifyEmailMfaSetupCommand,
    VerifyTotpSetupCommand,
};
use crate::modules::auth::infrastructure::auth_extractor::AuthenticatedUser;
use crate::modules::auth::infrastructure::AppState;

use super::api_error::ApiError;

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
