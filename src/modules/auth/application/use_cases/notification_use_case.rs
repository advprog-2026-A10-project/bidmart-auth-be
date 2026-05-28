use std::sync::Arc;

use crate::modules::auth::application::dto::{
    AuthenticatedUserContext, MessageResponseDto, NotificationPreferencesDto,
    NotificationPreferencesResponseDto, UpdateNotificationPreferencesCommand,
};
use crate::modules::auth::application::use_cases::helpers::require_settings_user;
use crate::modules::auth::domain::entities::NotificationPreferences;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{NotificationPreferencesRepository, UserRepository};

pub struct NotificationUseCase {
    user_repository: Arc<dyn UserRepository>,
    notification_preferences_repository: Arc<dyn NotificationPreferencesRepository>,
}

impl NotificationUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        notification_preferences_repository: Arc<dyn NotificationPreferencesRepository>,
    ) -> Self {
        Self {
            user_repository,
            notification_preferences_repository,
        }
    }

    pub async fn get_notification_preferences(
        &self,
        auth: AuthenticatedUserContext,
    ) -> Result<NotificationPreferencesResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        let preferences = self
            .notification_preferences_repository
            .get_by_user_id(user.id)
            .await?;
        Ok(NotificationPreferencesResponseDto {
            preferences: preferences.into(),
        })
    }

    pub async fn update_notification_preferences(
        &self,
        auth: AuthenticatedUserContext,
        command: UpdateNotificationPreferencesCommand,
    ) -> Result<MessageResponseDto, AuthError> {
        let user = require_settings_user(&self.user_repository, &auth).await?;
        self.notification_preferences_repository
            .upsert(user.id, command.preferences.into())
            .await?;
        Ok(MessageResponseDto {
            message: "Notification preferences updated.".to_string(),
        })
    }
}

impl From<NotificationPreferences> for NotificationPreferencesDto {
    fn from(p: NotificationPreferences) -> Self {
        Self {
            email_notifications: p.email_notifications,
            push_notifications: p.push_notifications,
            marketing_emails: p.marketing_emails,
            security_alerts: p.security_alerts,
        }
    }
}

impl From<NotificationPreferencesDto> for NotificationPreferences {
    fn from(p: NotificationPreferencesDto) -> Self {
        Self {
            email_notifications: p.email_notifications,
            push_notifications: p.push_notifications,
            marketing_emails: p.marketing_emails,
            security_alerts: p.security_alerts,
        }
    }
}
