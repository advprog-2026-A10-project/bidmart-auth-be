use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateProfileCommand {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    pub address: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsProfileUserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub address: String,
    #[serde(rename = "postalCode")]
    pub postal_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsProfileResponseDto {
    pub user: SettingsProfileUserDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateProfileResponseDto {
    pub message: String,
    pub user: SettingsProfileUserDto,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordCommand {
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}
