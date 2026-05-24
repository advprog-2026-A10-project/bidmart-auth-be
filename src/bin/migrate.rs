use bidmart_auth_be::infrastructure::config::AppConfig;
use bidmart_auth_be::infrastructure::database::create_pool;
use bidmart_auth_be::infrastructure::database::migrations::run_pending_migrations;
use bidmart_auth_be::infrastructure::logger::init_tracer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();
    let config = AppConfig::new()?;
    let pool = create_pool(&config.database_url).await?;

    run_pending_migrations(&pool).await?;
    tracing::info!("Auth database migrations applied successfully");
    Ok(())
}

