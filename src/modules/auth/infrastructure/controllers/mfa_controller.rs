use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Json;
use validator::Validate;

use crate::modules::auth::application::dto::{
    AccessTokenResponseDto, MessageResponseDto, SendEmailMfaCommand, VerifyEmailMfaCommand,
    VerifyTotpMfaCommand,
};
use crate::modules::auth::infrastructure::AppState;

use super::api_error::ApiError;
use super::helpers::{extract_session_context, with_session_cookie};

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
    headers: HeaderMap,
    payload: Result<Json<VerifyEmailMfaCommand>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .verify_email_mfa(command, extract_session_context(&headers))
        .await
        .map_err(ApiError::from_auth_error)?;
    let response = AccessTokenResponseDto::from(result);
    let access_token = response.access_token.clone();
    Ok(with_session_cookie(&state, &access_token, Json(response)))
}

pub async fn verify_totp_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<VerifyTotpMfaCommand>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let result = state
        .auth_mfa_use_case
        .verify_totp_mfa(command, extract_session_context(&headers))
        .await
        .map_err(ApiError::from_auth_error)?;
    let response = AccessTokenResponseDto::from(result);
    let access_token = response.access_token.clone();
    Ok(with_session_cookie(&state, &access_token, Json(response)))
}
