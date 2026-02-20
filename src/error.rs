use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    NotFound(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Sqlx(err) => map_sqlx_error(&err),
            Self::Other(err) => {
                tracing::error!(error = %err, "unexpected application error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };

        (status, Json(ErrorBody { error: message })).into_response()
    }
}

fn map_sqlx_error(err: &sqlx::Error) -> (StatusCode, String) {
    if let sqlx::Error::Database(db_err) = err {
        if db_err.code().as_deref() == Some("23505") {
            return (StatusCode::CONFLICT, "resource already exists".to_owned());
        }
    }

    tracing::error!(error = %err, "database operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "database error".to_owned(),
    )
}
