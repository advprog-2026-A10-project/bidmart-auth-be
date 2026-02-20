mod auth;
mod config;
mod error;
mod handlers;
mod models;
mod state;

use std::sync::Arc;

use anyhow::Context;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::Config, handlers::build_router, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Arc::new(Config::from_env().context("failed to load configuration")?);
    let pool = connect_pool(&config).await?;
    run_migrations(&pool).await?;

    let addr = format!("{}:{}", config.app_host, config.app_port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind listener at {addr}"))?;

    let state = AppState { pool, config };
    let app = build_router(state);

    info!(%addr, "bidmart-auth-be is running");
    axum::serve(listener, app)
        .await
        .context("http server failed")?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn connect_pool(config: &Config) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await
        .context("failed to connect to postgres")?;

    Ok(pool)
}

async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("database migrations failed")
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use sqlx::postgres::PgPoolOptions;

    use super::{connect_pool, run_migrations};

    fn bad_db_config() -> Config {
        Config {
            app_host: "127.0.0.1".to_owned(),
            app_port: 8080,
            database_url: "postgres://postgres:postgres@localhost:5432/postgres".to_owned(),
            database_max_connections: 1,
            jwt_secret: "01234567890123456789012345678901".to_owned(),
            jwt_expiry_minutes: 30,
            cors_origin: "*".to_owned(),
        }
    }

    #[tokio::test]
    async fn connect_pool_returns_error_when_db_is_unavailable() {
        let cfg = bad_db_config();
        let err = connect_pool(&cfg).await.expect_err("must fail");
        assert!(err.to_string().contains("failed to connect to postgres"));
    }

    #[tokio::test]
    async fn run_migrations_returns_error_when_db_is_unavailable() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
            .expect("pool should be created");

        let err = run_migrations(&pool).await.expect_err("must fail");
        assert!(err.to_string().contains("database migrations failed"));
    }
}
