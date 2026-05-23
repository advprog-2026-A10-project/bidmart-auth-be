use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use validator::Validate;

use crate::modules::auth::application::dto::{
    ForgotPasswordCommand, LoginCommand, LoginResponseDto, MessageResponseDto,
    ResetPasswordCommand, ValidateSessionResponseDto, LOGOUT_SUCCESS_MESSAGE,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::infrastructure::auth_extractor::AuthenticatedUser;
use crate::modules::auth::infrastructure::AppState;

use super::api_error::ApiError;
use super::helpers::{extract_session_context, with_clear_session_cookie, with_session_cookie};

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<LoginCommand>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .auth_mfa_use_case
        .login(command, extract_session_context(&headers))
        .await
        .map_err(ApiError::from_auth_error)?;

    let response = LoginResponseDto::from(result);
    if response.requires_mfa {
        return Ok(Json(response).into_response());
    }

    let access_token = response
        .access_token
        .as_deref()
        .map(ToString::to_string)
        .ok_or_else(|| ApiError::from_auth_error(AuthError::Unauthorized))?;
    Ok(with_session_cookie(&state, &access_token, Json(response)))
}

pub async fn logout(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Response, ApiError> {
    let jti_hash = auth
        .session_jti_hash
        .as_deref()
        .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;
    let now = state.clock.now();
    let session = state
        .session_repository
        .find_active_by_jti_hash(jti_hash, now)
        .await
        .map_err(ApiError::from_auth_error)?
        .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;

    let revoked = state
        .session_repository
        .revoke_session(auth.user_id, session.id, None, now)
        .await
        .map_err(ApiError::from_auth_error)?;
    if !revoked {
        return Err(ApiError::from_auth_error(AuthError::SessionInvalid));
    }

    Ok(with_clear_session_cookie(
        &state,
        Json(MessageResponseDto {
            message: LOGOUT_SUCCESS_MESSAGE.to_string(),
        }),
    ))
}

pub async fn validate_session(
    State(state): State<AppState>,
    AuthenticatedUser(auth): AuthenticatedUser,
) -> Result<Json<ValidateSessionResponseDto>, ApiError> {
    let jti_hash = auth
        .session_jti_hash
        .as_deref()
        .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;
    let session = state
        .session_repository
        .find_active_by_jti_hash(jti_hash, state.clock.now())
        .await
        .map_err(ApiError::from_auth_error)?
        .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;
    let user = state
        .auth_mfa_use_case
        .resolve_authenticated_user(auth.clone())
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(ValidateSessionResponseDto {
        user_id: user.id,
        name: user.name,
        email: user.email,
        email_verified: user.email_verified,
        mfa_satisfied: auth.mfa_satisfied,
        session_expiry: session.expires_at.to_rfc3339(),
    }))
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
