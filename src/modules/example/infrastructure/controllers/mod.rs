use std::collections::BTreeMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use validator::{Validate, ValidationErrors};

use crate::modules::auth::application::dto::{
    MessageResponseDto, RegisterResponseDto, RegisterUserCommand, ResendVerificationCommand,
    VerifyEmailCommand,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::infrastructure::AppState;

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<BTreeMap<String, Vec<String>>>,
}

pub async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterUserCommand>, JsonRejection>,
) -> Result<(StatusCode, Json<RegisterResponseDto>), ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .register_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok((StatusCode::CREATED, Json(result.into())))
}

pub async fn verify_email(
    State(state): State<AppState>,
    payload: Result<Json<VerifyEmailCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .verify_email_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub async fn resend_verification(
    State(state): State<AppState>,
    payload: Result<Json<ResendVerificationCommand>, JsonRejection>,
) -> Result<Json<MessageResponseDto>, ApiError> {
    let Json(command) = payload.map_err(ApiError::from_json_rejection)?;
    command
        .validate()
        .map_err(ApiError::from_validation_errors)?;

    let result = state
        .resend_verification_use_case
        .execute(command)
        .await
        .map_err(ApiError::from_auth_error)?;

    Ok(Json(result.into()))
}

pub enum ApiError {
    Validation {
        message: String,
        errors: BTreeMap<String, Vec<String>>,
    },
    Message {
        status: StatusCode,
        message: String,
    },
}

impl ApiError {
    fn from_json_rejection(rejection: JsonRejection) -> Self {
        Self::Message {
            status: rejection.status(),
            message: "Invalid JSON payload.".to_string(),
        }
    }

    fn from_validation_errors(errors: ValidationErrors) -> Self {
        let mut field_errors = BTreeMap::new();
        for (field, errors_for_field) in errors.field_errors() {
            let messages = errors_for_field
                .iter()
                .map(|error| {
                    error
                        .message
                        .as_ref()
                        .map(|message| message.to_string())
                        .unwrap_or_else(|| "Invalid value.".to_string())
                })
                .collect::<Vec<_>>();
            field_errors.insert(field.to_string(), messages);
        }

        Self::Validation {
            message: "Validation error".to_string(),
            errors: field_errors,
        }
    }

    fn from_auth_error(error: AuthError) -> Self {
        match error {
            AuthError::InvalidName => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("name", "Name is required"),
            },
            AuthError::InvalidEmail => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("email", "Email must be a valid email address"),
            },
            AuthError::WeakPassword => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("password", "Password must be at least 8 characters"),
            },
            AuthError::EmailAlreadyExists => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("email", "Email already exists"),
            },
            AuthError::VerificationTokenExpired => Self::Message {
                status: StatusCode::GONE,
                message: "Verification token expired.".to_string(),
            },
            AuthError::VerificationTokenInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token invalid.".to_string(),
            },
            AuthError::VerificationTokenAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token already used.".to_string(),
            },
            AuthError::VerificationCooldownActive => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification email was sent recently. Please wait before trying again."
                    .to_string(),
            },
            AuthError::UserAlreadyVerified => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Email is already verified.".to_string(),
            },
            AuthError::UserNotFound => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token invalid.".to_string(),
            },
            AuthError::DependencyFailure(_) => Self::Message {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error.".to_string(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Validation { message, errors } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorEnvelope {
                    message,
                    errors: Some(errors),
                }),
            )
                .into_response(),
            Self::Message { status, message } => (
                status,
                Json(ErrorEnvelope {
                    message,
                    errors: None,
                }),
            )
                .into_response(),
        }
    }
}

fn field_map(field: &str, message: &str) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([(field.to_string(), vec![message.to_string()])])
}
