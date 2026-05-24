use std::sync::Arc;

use crate::modules::auth::application::dto::AuthenticatedUserContext;
use crate::modules::auth::domain::entities::User;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::UserRepository;

pub(super) fn require_login_allowed(user: &User) -> Result<(), AuthError> {
    if !user.status.is_active() {
        return Err(AuthError::UserDisabled);
    }
    if !user.is_email_verified() {
        return Err(AuthError::EmailNotVerified);
    }
    Ok(())
}

pub(super) async fn require_settings_user(
    user_repository: &Arc<dyn UserRepository>,
    auth: &AuthenticatedUserContext,
) -> Result<User, AuthError> {
    let user = user_repository
        .find_by_id(auth.user_id)
        .await?
        .ok_or(AuthError::Unauthorized)?;
    require_login_allowed(&user)?;
    if user.has_mfa_enabled() && !auth.mfa_satisfied {
        return Err(AuthError::Forbidden);
    }
    Ok(user)
}
