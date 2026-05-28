use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreferencesDto {
    #[serde(rename = "emailNotifications")]
    pub email_notifications: bool,
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
    #[serde(rename = "marketingEmails")]
    pub marketing_emails: bool,
    #[serde(rename = "securityAlerts")]
    pub security_alerts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotificationPreferencesResponseDto {
    pub preferences: NotificationPreferencesDto,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateNotificationPreferencesCommand {
    pub preferences: NotificationPreferencesDto,
}
