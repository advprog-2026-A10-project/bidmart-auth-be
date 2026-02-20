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
    if let sqlx::Error::Database(db_err) = err
        && db_err.code().as_deref() == Some("23505")
    {
        return (StatusCode::CONFLICT, "resource already exists".to_owned());
    }

    tracing::error!(error = %err, "database operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "database error".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    use super::AppError;

    #[tokio::test]
    async fn bad_request_maps_to_400() {
        let response = AppError::BadRequest("invalid input".to_owned()).into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("invalid input"));
    }

    #[tokio::test]
    async fn unauthorized_maps_to_401() {
        let response = AppError::Unauthorized("no token".to_owned()).into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn not_found_maps_to_404() {
        let response = AppError::NotFound("missing".to_owned()).into_response();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sqlx_maps_to_database_error() {
        let response = AppError::Sqlx(sqlx::Error::RowNotFound).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("database error"));
    }

    #[tokio::test]
    async fn other_maps_to_internal_server_error() {
        let response = AppError::Other(anyhow::anyhow!("unexpected")).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("internal server error"));
    }
}
