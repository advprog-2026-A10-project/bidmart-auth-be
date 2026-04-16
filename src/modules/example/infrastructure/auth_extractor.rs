use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;

use crate::modules::auth::application::dto::AuthenticatedUserContext;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::infrastructure::controllers::ApiError;
use crate::modules::auth::infrastructure::AppState;

pub struct AuthenticatedUser(pub AuthenticatedUserContext);

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| ApiError::from_auth_error(AuthError::Unauthorized))?;

        let context = state
            .jwt_service
            .verify_access_token(token, state.clock.now())
            .map_err(ApiError::from_auth_error)?;

        let jti_hash = context
            .session_jti_hash
            .as_deref()
            .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;

        let session = state
            .session_repository
            .find_active_by_jti_hash(jti_hash, state.clock.now())
            .await
            .map_err(ApiError::from_auth_error)?
            .ok_or_else(|| ApiError::from_auth_error(AuthError::SessionInvalid))?;

        if session.user_id != context.user_id || session.mfa_satisfied != context.mfa_satisfied {
            return Err(ApiError::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Unauthorized.".to_string(),
            });
        }

        Ok(Self(context))
    }
}
