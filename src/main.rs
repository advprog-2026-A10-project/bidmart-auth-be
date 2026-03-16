use axum::serve;
use tokio::net::TcpListener;

use bidmart_auth_be::infrastructure::config::AppConfig;
use bidmart_auth_be::infrastructure::database::create_pool;
use bidmart_auth_be::infrastructure::logger::init_tracer;
use bidmart_auth_be::modules::example::infrastructure::create_router;
use bidmart_auth_be::modules::example::infrastructure::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();

    let config = AppConfig::new()?;

    let pool = create_pool(&config.database_url).await?;

    let app_state = AppState { _auth_pool: pool };

    let router = create_router(app_state);

    let address = format!("{}:{}", config.server_host, config.server_port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!("Starting server on {}", address);

    serve(listener, router).await?;

    Ok(())
}
