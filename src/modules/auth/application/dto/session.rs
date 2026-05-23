use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionDto {
    pub id: Uuid,
    pub device: String,
    pub browser: String,
    pub os: String,
    pub ip: String,
    pub location: String,
    #[serde(rename = "lastActive")]
    pub last_active: String,
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionsResponseDto {
    pub sessions: Vec<SessionDto>,
}
