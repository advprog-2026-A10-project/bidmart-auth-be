use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use validator::Validate;

use crate::modules::auth::application::dto::{
    AccessTokenResponseDto, MessageResponseDto, RegisterRequestCommand, RegisterResponseDto,
    ResendVerificationCommand, VerifyEmailCommand,
};
use crate::modules::auth::infrastructure::AppState;

use super::api_error::ApiError;
use super::helpers::{extract_session_context, with_session_cookie};

pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterRequestCommand>, JsonRejection>,
) -> Result<(StatusCode, Json<RegisterResponseDto>), ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;
    let command = command
        .into_use_case_command()
        .map_err(ApiError::from_register_command_error)?;

    let result = state
        .register_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok((StatusCode::CREATED, Json(result.into())))
}

pub async fn verify_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<VerifyEmailCommand>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .verify_email_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    let issued = state
        .auth_mfa_use_case
        .issue_post_verification_session(result.user_id, extract_session_context(&headers))
        .await
        .map_err(ApiError::from_auth_error)?;

    let response = AccessTokenResponseDto::from(issued);
    let access_token = response.access_token.clone();
    Ok(with_session_cookie(&state, &access_token, Json(response)))
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
