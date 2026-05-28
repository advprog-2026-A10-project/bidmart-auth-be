use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::modules::auth::application::dto::AuthenticatedUserContext;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::infrastructure::controllers::ApiError;
use crate::modules::auth::infrastructure::session_cookie::extract_token_from_headers;
use crate::modules::auth::infrastructure::AppState;

pub struct AuthenticatedUser(pub AuthenticatedUserContext);

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token_from_headers(&parts.headers, &state.session_cookie_name)
            .ok_or_else(|| ApiError::from_auth_error(AuthError::Unauthorized))?;

        let context = state
            .session_use_case
            .authenticate(&token)
            .await
            .map_err(ApiError::from_auth_error)?;

        Ok(Self(context))
    }
}
