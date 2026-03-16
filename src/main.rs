mod infrastructure;
mod modules;
mod shared;

use std::sync::Arc;

use axum::serve;
use chrono::Duration;
use resend_rs::Resend;
use std::path::Path;
use tokio::net::TcpListener;

use infrastructure::config::AppConfig;
use infrastructure::database::create_pool;
use infrastructure::logger::init_tracer;
use modules::auth::application::use_cases::policy::AuthPolicy;
use modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use modules::auth::infrastructure::create_router;
use modules::auth::infrastructure::repositories::{
    PostgresEmailVerificationTokenRepository, PostgresUserRepository,
};
use modules::auth::infrastructure::services::{
    RandomVerificationTokenGenerator, ResendVerificationEmailSender, ScryptPasswordHasher,
    Sha256VerificationTokenHasher, SystemClock,
};
use modules::auth::infrastructure::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();

    let config = AppConfig::new()?;

    let pool = create_pool(&config.database_url).await?;
    let migrator = sqlx::migrate::Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&pool).await?;

    let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));
    let token_repository = Arc::new(PostgresEmailVerificationTokenRepository::new(pool));
    let password_hasher = Arc::new(ScryptPasswordHasher);
    let token_generator = Arc::new(RandomVerificationTokenGenerator);
    let token_hasher = Arc::new(Sha256VerificationTokenHasher);
    let resend_client = Resend::new(&config.resend_api_key);
    let email_sender = Arc::new(ResendVerificationEmailSender::new(
        resend_client,
        config.resend_from_email.clone(),
        config.verify_email_url_base.clone(),
    ));
    let clock = Arc::new(SystemClock);
    let auth_policy = AuthPolicy {
        min_password_length: config.auth_min_password_length,
        verification_token_ttl: Duration::seconds(config.auth_verification_token_ttl_seconds),
        resend_cooldown: Duration::seconds(config.auth_resend_cooldown_seconds),
    };

    let register_use_case = Arc::new(RegisterUserUseCase::new(
        user_repository.clone(),
        token_repository.clone(),
        password_hasher,
        token_generator.clone(),
        token_hasher.clone(),
        email_sender.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let verify_email_use_case = Arc::new(VerifyEmailUseCase::new(
        user_repository.clone(),
        token_repository.clone(),
        token_hasher.clone(),
        clock.clone(),
    ));
    let resend_verification_use_case = Arc::new(ResendVerificationUseCase::new(
        user_repository,
        token_repository,
        token_generator,
        token_hasher,
        email_sender,
        clock,
        auth_policy,
    ));

    let app_state = AppState::new(
        register_use_case,
        verify_email_use_case,
        resend_verification_use_case,
    );

    let router = create_router(app_state);

    let address = format!("{}:{}", config.server_host, config.server_port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!("Starting server on {}", address);

    serve(listener, router).await?;

    Ok(())
}
