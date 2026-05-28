use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicUserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageResponseDto {
    pub message: String,
}
