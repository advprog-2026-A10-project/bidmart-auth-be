use axum::http::StatusCode;

#[allow(dead_code)]
pub fn handle_error<E: std::fmt::Debug>(err: E) -> (StatusCode, String) {
    tracing::error!("Error: {:?}", err);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error".to_string(),
    )
}
