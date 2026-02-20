use axum::{Json, extract::State};

use crate::{error::AppError, models::HealthResponse, state::AppState};

pub async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;

    Ok(Json(HealthResponse { status: "ok" }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use sqlx::postgres::PgPoolOptions;

    use crate::{config::Config, state::AppState};

    use super::health;

    #[tokio::test]
    async fn health_returns_sqlx_error_when_db_is_unavailable() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
            .expect("pool should be created");

        let config = Arc::new(Config {
            app_host: "127.0.0.1".to_owned(),
            app_port: 8080,
            database_url: "postgres://postgres:postgres@localhost:5432/postgres".to_owned(),
            database_max_connections: 1,
            jwt_secret: "01234567890123456789012345678901".to_owned(),
            jwt_expiry_minutes: 30,
            cors_origin: "*".to_owned(),
        });

        let state = AppState { pool, config };
        let err = health(State(state)).await.expect_err("must fail");
        assert!(matches!(err, crate::error::AppError::Sqlx(_)));
    }
}
