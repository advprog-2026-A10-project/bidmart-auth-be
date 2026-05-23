use std::sync::Arc;

use uuid::Uuid;

use crate::modules::auth::application::dto::{
    AuthenticatedUserContext, MessageResponseDto, SessionDto, SessionsResponseDto,
    ValidateSessionResponseDto,
};
use crate::modules::auth::application::use_cases::helpers::require_settings_user;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{Clock, JwtService, SessionRepository, UserRepository};

pub struct SessionUseCase {
    user_repository: Arc<dyn UserRepository>,
    session_repository: Arc<dyn SessionRepository>,
    jwt_service: Arc<dyn JwtService>,
    clock: Arc<dyn Clock>,
}

impl SessionUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        session_repository: Arc<dyn SessionRepository>,
        jwt_service: Arc<dyn JwtService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            user_repository,
            session_repository,
            jwt_service,
            clock,
        }
    }

    /// Validates a JWT token and checks the corresponding session record.
    /// Used by the auth extractor on every authenticated request.
    pub async fn authenticate(&self, token: &str) -> Result<AuthenticatedUserContext, AuthError> {
        let context = self
            .jwt_service
            .verify_access_token(token, self.clock.now())?;

        let jti_hash = context
            .session_jti_hash
            .as_deref()
            .ok_or(AuthError::SessionInvalid)?;

        let session = self
            .session_repository
            .find_active_by_jti_hash(jti_hash, self.clock.now())
            .await?
            .ok_or(AuthError::SessionInvalid)?;

        if session.user_id != context.user_id || session.mfa_satisfied != context.mfa_satisfied {
            return Err(AuthError::Unauthorized);
        }

        Ok(context)
    }

    pub async fn logout(&self, auth: AuthenticatedUserContext) -> Result<(), AuthError> {
        let jti_hash = auth
            .session_jti_hash
            .as_deref()
            .ok_or(AuthError::SessionInvalid)?;
        let now = self.clock.now();
        let session = self
            .session_repository
            .find_active_by_jti_hash(jti_hash, now)
            .await?
            .ok_or(AuthError::SessionInvalid)?;
        let revoked = self
            .session_repository
            .revoke_session(auth.user_id, session.id, None, now)
            .await?;
        if !revoked {
            return Err(AuthError::SessionInvalid);
        }
        Ok(())
    }

    pub async fn get_session_info(
        &self,
        auth: &AuthenticatedUserContext,
    ) -> Result<ValidateSessionResponseDto, AuthError> {
        let jti_hash = auth
            .session_jti_hash
            .as_deref()
            .ok_or(AuthError::SessionInvalid)?;
        let session = self
            .session_repository
            .find_active_by_jti_hash(jti_hash, self.clock.now())
            .await?
            .ok_or(AuthError::SessionInvalid)?;
        let user = self
            .user_repository
            .find_by_id(auth.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let name = user.display_name();
        let email_verified = user.is_email_verified();
        Ok(ValidateSessionResponseDto {
            user_id: user.id,
            name,
            email: user.email,
            email_verified,
            mfa_satisfied: auth.mfa_satisfied,
            session_expiry: session.expires_at.to_rfc3339(),
        })
    }

    pub async fn get_sessions(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<SessionsResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        let current_jti_hash = auth.session_jti_hash.as_deref();
        let sessions = self
            .session_repository
            .list_active_by_user_id(user.id, self.clock.now())
            .await?
            .into_iter()
            .map(|session| SessionDto {
                id: session.id,
                device: session.device,
                browser: session.browser,
                os: session.os,
                ip: session.ip,
                location: session.location,
                last_active: session.last_active_at.to_rfc3339(),
                is_current: current_jti_hash == Some(session.jti_hash.as_str()),
            })
            .collect();
        Ok(SessionsResponseDto { sessions })
    }

    pub async fn revoke_session(
        &self,
        auth: AuthenticatedUserContext,
        session_id: Uuid,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        let revoked = self
            .session_repository
            .revoke_session(
                user.id,
                session_id,
                auth.session_jti_hash.as_deref(),
                self.clock.now(),
            )
            .await?;
        if !revoked {
            return Err(AuthError::SessionNotFound);
        }
        Ok(MessageResponseDto {
            message: "Session revoked.".to_string(),
        })
    }

    pub async fn revoke_all_sessions(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        self.session_repository
            .revoke_all_other_sessions(
                user.id,
                auth.session_jti_hash.as_deref(),
                self.clock.now(),
            )
            .await?;
        Ok(MessageResponseDto {
            message: "Sessions revoked.".to_string(),
        })
    }
}
