use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use validator::ValidationErrors;

use crate::modules::auth::application::dto::RegisterCommandError;
use crate::modules::auth::domain::errors::AuthError;

#[derive(Debug, Serialize)]
pub(super) struct ErrorEnvelope {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<BTreeMap<String, Vec<String>>>,
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
    pub fn from_json_rejection(rejection: axum::extract::rejection::JsonRejection) -> Self {
        tracing::warn!(
            status = rejection.status().as_u16(),
            reason = %rejection,
            "invalid_json_payload"
        );
        Self::Message {
            status: rejection.status(),
            message: "Invalid JSON payload.".to_string(),
        }
    }

    pub fn from_validation_errors(errors: ValidationErrors) -> Self {
        tracing::warn!(errors = ?errors, "validation_error");
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

    pub fn from_register_command_error(error: RegisterCommandError) -> Self {
        match error {
            RegisterCommandError::ConfirmPasswordRequired => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("confirmPassword", "Confirm password is required"),
            },
            RegisterCommandError::PasswordsDoNotMatch => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("confirmPassword", "Passwords do not match"),
            },
            RegisterCommandError::NameRequired => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("name", "Name is required"),
            },
            RegisterCommandError::FirstNameRequired => Self::Validation {
                message: "Validation error".to_string(),
                errors: field_map("firstName", "First name is required"),
            },
        }
    }

    pub fn from_auth_error(error: AuthError) -> Self {
        let error_description = error.to_string();
        let mapped = match error {
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
            AuthError::PasswordResetTokenExpired => Self::Message {
                status: StatusCode::GONE,
                message: "Password reset token expired.".to_string(),
            },
            AuthError::PasswordResetTokenInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Password reset token invalid.".to_string(),
            },
            AuthError::PasswordResetTokenAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Password reset token already used.".to_string(),
            },
            AuthError::UserAlreadyVerified => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Email is already verified.".to_string(),
            },
            AuthError::UserNotFound => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "Verification token invalid.".to_string(),
            },
            AuthError::InvalidCredentials => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Invalid email or password.".to_string(),
            },
            AuthError::EmailNotVerified => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "Email must be verified before login.".to_string(),
            },
            AuthError::UserDisabled => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "User account is disabled.".to_string(),
            },
            AuthError::MfaTicketInvalid | AuthError::TotpSetupInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA ticket invalid.".to_string(),
            },
            AuthError::MfaTicketExpired => Self::Message {
                status: StatusCode::GONE,
                message: "MFA ticket expired.".to_string(),
            },
            AuthError::MfaCodeInvalid => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code invalid.".to_string(),
            },
            AuthError::MfaCodeExpired => Self::Message {
                status: StatusCode::GONE,
                message: "MFA code expired.".to_string(),
            },
            AuthError::MfaCodeAlreadyUsed => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code already used.".to_string(),
            },
            AuthError::MfaCodeCooldownActive => Self::Message {
                status: StatusCode::BAD_REQUEST,
                message: "MFA code was sent recently. Please wait before trying again.".to_string(),
            },
            AuthError::CurrentPasswordRequired => Self::Message {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: "Current password is required.".to_string(),
            },
            AuthError::CurrentPasswordInvalid => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Current password is invalid.".to_string(),
            },
            AuthError::Unauthorized | AuthError::SessionInvalid => Self::Message {
                status: StatusCode::UNAUTHORIZED,
                message: "Unauthorized.".to_string(),
            },
            AuthError::SessionNotFound => Self::Message {
                status: StatusCode::NOT_FOUND,
                message: "Session not found.".to_string(),
            },
            AuthError::ConcurrentSessionLimitReached => Self::Message {
                status: StatusCode::FORBIDDEN,
                message:
                    "Maximum concurrent sessions reached. Please sign out from another device."
                        .to_string(),
            },
            AuthError::Forbidden => Self::Message {
                status: StatusCode::FORBIDDEN,
                message: "Forbidden.".to_string(),
            },
            AuthError::DependencyFailure(_) => Self::Message {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error.".to_string(),
            },
        };

        let status = mapped.status_code();
        if status.is_server_error() {
            tracing::error!(
                status = status.as_u16(),
                error = %error_description,
                "auth_error_mapped_to_server_response"
            );
        } else {
            tracing::warn!(
                status = status.as_u16(),
                error = %error_description,
                "auth_error_mapped_to_client_response"
            );
        }

        mapped
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Message { status, .. } => *status,
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

pub fn field_map(field: &str, message: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    std::collections::BTreeMap::from([(field.to_string(), vec![message.to_string()])])
}
