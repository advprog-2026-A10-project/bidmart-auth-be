use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use validator::Validate;

use crate::modules::auth::application::dto::MessageResponseDto;
use crate::modules::auth::infrastructure::AppState;

use super::api_error::ApiError;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RoleMutationCommand {
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PermissionMutationCommand {
    #[validate(length(min = 1, message = "Permission is required"))]
    pub permission: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationEventEnvelope {
    event_id: Uuid,
    event_type: String,
    occurred_at: String,
    producer: String,
    entity_id: String,
    data: serde_json::Value,
}

pub async fn assign_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    payload: Result<Json<RoleMutationCommand>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    require_internal_token(&state, &headers)?;
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let changed = state
        .authorization_repository
        .assign_role_to_user(user_id, command.role.trim())
        .await
        .map_err(ApiError::from_auth_error)?;

    publish_user_role_event(&state, user_id, command.role.trim(), "ASSIGNED").await;

    Ok(Json(MessageResponseDto {
        message: if changed {
            "Role assigned.".to_string()
        } else {
            "Role assignment unchanged.".to_string()
        },
    }))
}

pub async fn revoke_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    payload: Result<Json<RoleMutationCommand>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    require_internal_token(&state, &headers)?;
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let changed = state
        .authorization_repository
        .revoke_role_from_user(user_id, command.role.trim())
        .await
        .map_err(ApiError::from_auth_error)?;

    publish_user_role_event(&state, user_id, command.role.trim(), "REVOKED").await;

    Ok(Json(MessageResponseDto {
        message: if changed {
            "Role revoked.".to_string()
        } else {
            "Role revoke unchanged.".to_string()
        },
    }))
}

pub async fn assign_role_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(role_name): Path<String>,
    payload: Result<Json<PermissionMutationCommand>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    require_internal_token(&state, &headers)?;
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let changed = state
        .authorization_repository
        .assign_permission_to_role(role_name.trim(), command.permission.trim())
        .await
        .map_err(ApiError::from_auth_error)?;

    publish_role_permission_event(
        &state,
        role_name.trim(),
        command.permission.trim(),
        "ASSIGNED",
    )
    .await;

    Ok(Json(MessageResponseDto {
        message: if changed {
            "Permission assigned to role.".to_string()
        } else {
            "Role permission assignment unchanged.".to_string()
        },
    }))
}

pub async fn revoke_role_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(role_name): Path<String>,
    payload: Result<Json<PermissionMutationCommand>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    require_internal_token(&state, &headers)?;
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let changed = state
        .authorization_repository
        .revoke_permission_from_role(role_name.trim(), command.permission.trim())
        .await
        .map_err(ApiError::from_auth_error)?;

    publish_role_permission_event(
        &state,
        role_name.trim(),
        command.permission.trim(),
        "REVOKED",
    )
    .await;

    Ok(Json(MessageResponseDto {
        message: if changed {
            "Permission revoked from role.".to_string()
        } else {
            "Role permission revoke unchanged.".to_string()
        },
    }))
}

fn require_internal_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(configured_token) = state.internal_service_token.as_deref() else {
        return Err(ApiError::Message {
            status: axum::http::StatusCode::FORBIDDEN,
            message: "Internal access is not configured.".to_string(),
        });
    };

    let provided = headers
        .get("x-internal-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if provided
        .as_bytes()
        .ct_eq(configured_token.as_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(ApiError::Message {
            status: axum::http::StatusCode::UNAUTHORIZED,
            message: "Unauthorized internal call.".to_string(),
        })
    }
}

async fn publish_user_role_event(state: &AppState, user_id: Uuid, role: &str, action: &str) {
    let Some(amqp) = &state.amqp else {
        return;
    };

    let event = AuthorizationEventEnvelope {
        event_id: Uuid::new_v4(),
        event_type: "auth.user_role_changed".to_string(),
        occurred_at: chrono::Utc::now().to_rfc3339(),
        producer: "bidmart-auth-be".to_string(),
        entity_id: user_id.to_string(),
        data: serde_json::json!({
            "userId": user_id,
            "role": role,
            "action": action
        }),
    };

    amqp.publish(
        "auth.user_role_changed",
        serde_json::to_value(event).unwrap_or(serde_json::json!({})),
    );
}

async fn publish_role_permission_event(
    state: &AppState,
    role: &str,
    permission: &str,
    action: &str,
) {
    let Some(amqp) = &state.amqp else {
        return;
    };

    let event = AuthorizationEventEnvelope {
        event_id: Uuid::new_v4(),
        event_type: "auth.role_permissions_changed".to_string(),
        occurred_at: chrono::Utc::now().to_rfc3339(),
        producer: "bidmart-auth-be".to_string(),
        entity_id: role.to_string(),
        data: serde_json::json!({
            "role": role,
            "permission": permission,
            "action": action
        }),
    };

    amqp.publish(
        "auth.role_permissions_changed",
        serde_json::to_value(event).unwrap_or(serde_json::json!({})),
    );
}
