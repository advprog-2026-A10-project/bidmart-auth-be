use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::modules::auth::domain::entities::NotificationPreferences;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::NotificationPreferencesRepository;

use super::map_database_error;

#[derive(Clone)]
pub struct PostgresNotificationPreferencesRepository {
    pool: PgPool,
}

impl PostgresNotificationPreferencesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NotificationPreferencesRepository for PostgresNotificationPreferencesRepository {
    async fn get_by_user_id(&self, user_id: Uuid) -> Result<NotificationPreferences, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT email_notifications, push_notifications, marketing_emails, security_alerts
            FROM notification_preferences
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(row
            .map(|row| NotificationPreferences {
                email_notifications: row.get("email_notifications"),
                push_notifications: row.get("push_notifications"),
                marketing_emails: row.get("marketing_emails"),
                security_alerts: row.get("security_alerts"),
            })
            .unwrap_or_default())
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        preferences: NotificationPreferences,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO notification_preferences (
                user_id, email_notifications, push_notifications, marketing_emails, security_alerts
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE SET
                email_notifications = EXCLUDED.email_notifications,
                push_notifications = EXCLUDED.push_notifications,
                marketing_emails = EXCLUDED.marketing_emails,
                security_alerts = EXCLUDED.security_alerts,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(user_id)
        .bind(preferences.email_notifications)
        .bind(preferences.push_notifications)
        .bind(preferences.marketing_emails)
        .bind(preferences.security_alerts)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }
}
