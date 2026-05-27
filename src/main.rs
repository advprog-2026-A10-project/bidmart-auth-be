mod infrastructure;
mod modules;
mod shared;

use std::sync::Arc;

use axum::serve;
use chrono::Duration;
use resend_rs::Resend;
use tokio::net::TcpListener;

use infrastructure::amqp::AmqpPublisher;
use infrastructure::config::{AppConfig, EmailDeliveryMode};
use infrastructure::database::create_pool;
use infrastructure::database::migrations::run_pending_migrations;
use infrastructure::logger::init_tracer;
use modules::auth::application::use_cases::auth_mfa_use_case::AuthMfaUseCase;
use modules::auth::application::use_cases::mfa_setup_use_case::MfaSetupUseCase;
use modules::auth::application::use_cases::notification_use_case::NotificationUseCase;
use modules::auth::application::use_cases::password_reset_use_case::{
    ForgotPasswordUseCase, ResetPasswordUseCase,
};
use modules::auth::application::use_cases::policy::AuthPolicy;
use modules::auth::application::use_cases::profile_use_case::ProfileUseCase;
use modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use modules::auth::application::use_cases::session_use_case::SessionUseCase;
use modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use modules::auth::infrastructure::create_router_with_cors_origins;
use modules::auth::infrastructure::repositories::{
    PostgresAuthorizationRepository, PostgresEmailMfaCodeRepository,
    PostgresEmailVerificationTokenRepository, PostgresMfaTicketRepository,
    PostgresNotificationPreferencesRepository, PostgresPasswordResetTokenRepository,
    PostgresSessionRepository, PostgresTotpSetupRepository, PostgresUserRepository,
};
use modules::auth::infrastructure::services::{
    Hs256JwtService, RandomVerificationTokenGenerator, ResendVerificationEmailSender,
    ScryptPasswordHasher, Sha256VerificationTokenHasher, SystemClock, TotpRsService,
};
use modules::auth::infrastructure::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();

    let config = AppConfig::new()?;

    let amqp = match &config.amqp_url {
        Some(url) => match AmqpPublisher::connect(url, &config.amqp_exchange).await {
            Ok(publisher) => Some(publisher),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed to initialize AMQP publisher; continuing without events"
                );
                None
            }
        },
        None => None,
    };

    let pool = create_pool(&config.database_url).await?;
    if config.auto_migrate_on_startup {
        tracing::info!("APP_AUTO_MIGRATE_ON_STARTUP=true, running pending migrations");
        run_pending_migrations(&pool).await?;
    }

    let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));
    let authorization_repository = Arc::new(PostgresAuthorizationRepository::new(pool.clone()));
    let token_repository = Arc::new(PostgresEmailVerificationTokenRepository::new(pool.clone()));
    let password_reset_token_repository =
        Arc::new(PostgresPasswordResetTokenRepository::new(pool.clone()));
    let mfa_ticket_repository = Arc::new(PostgresMfaTicketRepository::new(pool.clone()));
    let email_mfa_code_repository = Arc::new(PostgresEmailMfaCodeRepository::new(pool.clone()));
    let session_repository = Arc::new(PostgresSessionRepository::new(pool.clone()));
    let notification_preferences_repository =
        Arc::new(PostgresNotificationPreferencesRepository::new(pool.clone()));
    let totp_setup_repository = Arc::new(PostgresTotpSetupRepository::new(pool));

    let scrypt = Arc::new(ScryptPasswordHasher);
    let password_hasher: Arc<dyn modules::auth::domain::traits::PasswordHasher> = scrypt.clone();
    let password_verifier: Arc<dyn modules::auth::domain::traits::PasswordVerifier> = scrypt;

    let token_generator = Arc::new(RandomVerificationTokenGenerator);
    let token_hasher = Arc::new(Sha256VerificationTokenHasher);
    let email_sender = Arc::new(match config.email_delivery_mode {
        EmailDeliveryMode::Resend => ResendVerificationEmailSender::with_resend(
            Resend::new(
                config
                    .resend_api_key
                    .as_deref()
                    .expect("resend api key should exist in resend mode"),
            ),
            config
                .resend_from_email
                .clone()
                .expect("resend from email should exist in resend mode"),
            config.verify_email_url_base.clone(),
            config.password_reset_url_base.clone(),
        ),
        EmailDeliveryMode::Log => ResendVerificationEmailSender::log_only(
            config.verify_email_url_base.clone(),
            config.password_reset_url_base.clone(),
        ),
    });
    let clock = Arc::new(SystemClock);
    let jwt_service = Arc::new(Hs256JwtService::new(
        &config.auth_jwt_secret,
        config.auth_access_token_ttl_seconds,
    ));
    let totp_service = Arc::new(TotpRsService);
    let auth_policy = AuthPolicy {
        min_password_length: config.auth_min_password_length,
        verification_token_ttl: Duration::seconds(config.auth_verification_token_ttl_seconds),
        resend_cooldown: Duration::seconds(config.auth_resend_cooldown_seconds),
        password_reset_token_ttl: Duration::seconds(config.auth_password_reset_token_ttl_seconds),
        password_reset_cooldown: Duration::seconds(config.auth_password_reset_cooldown_seconds),
        mfa_ticket_ttl: Duration::seconds(config.auth_mfa_ticket_ttl_seconds),
        email_mfa_code_ttl: Duration::seconds(config.auth_email_mfa_code_ttl_seconds),
        email_mfa_cooldown: Duration::seconds(config.auth_email_mfa_cooldown_seconds),
        access_token_ttl: Duration::seconds(config.auth_access_token_ttl_seconds),
        totp_setup_ttl: Duration::seconds(config.auth_totp_setup_ttl_seconds),
    };

    let register_use_case = Arc::new(RegisterUserUseCase::new(
        user_repository.clone(),
        token_repository.clone(),
        password_hasher.clone(),
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
        user_repository.clone(),
        token_repository.clone(),
        token_generator.clone(),
        token_hasher.clone(),
        email_sender.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let forgot_password_use_case = Arc::new(ForgotPasswordUseCase::new(
        user_repository.clone(),
        password_reset_token_repository.clone(),
        token_generator.clone(),
        token_hasher.clone(),
        email_sender.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let reset_password_use_case = Arc::new(ResetPasswordUseCase::new(
        user_repository.clone(),
        password_reset_token_repository.clone(),
        password_reset_token_repository,
        password_hasher.clone(),
        token_hasher.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let auth_mfa_use_case = Arc::new(AuthMfaUseCase::new(
        user_repository.clone(),
        mfa_ticket_repository.clone(),
        email_mfa_code_repository.clone(),
        session_repository.clone(),
        password_verifier.clone(),
        token_generator.clone(),
        token_hasher.clone(),
        email_sender.clone(),
        jwt_service.clone(),
        totp_service.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let profile_use_case = Arc::new(ProfileUseCase::new(
        user_repository.clone(),
        session_repository.clone(),
        password_hasher,
        password_verifier.clone(),
        clock.clone(),
        auth_policy.clone(),
    ));
    let session_use_case = Arc::new(SessionUseCase::new(
        user_repository.clone(),
        authorization_repository.clone(),
        session_repository.clone(),
        jwt_service,
        clock.clone(),
    ));
    let mfa_setup_use_case = Arc::new(MfaSetupUseCase::new(
        user_repository.clone(),
        email_mfa_code_repository,
        totp_setup_repository,
        password_verifier,
        token_generator,
        token_hasher,
        email_sender,
        totp_service,
        clock.clone(),
        auth_policy.clone(),
    ));
    let notification_use_case = Arc::new(NotificationUseCase::new(
        user_repository,
        notification_preferences_repository,
    ));

    let app_state = AppState::new(
        register_use_case,
        verify_email_use_case,
        resend_verification_use_case,
        forgot_password_use_case,
        reset_password_use_case,
        auth_mfa_use_case,
        profile_use_case,
        session_use_case,
        authorization_repository,
        mfa_setup_use_case,
        notification_use_case,
        config.auth_session_cookie_name.clone(),
        config.auth_session_cookie_secure,
        config.auth_session_cookie_same_site.clone(),
        config.auth_access_token_ttl_seconds,
        amqp,
        config.internal_service_token.clone(),
    );

    let router = create_router_with_cors_origins(app_state, &config.cors_allowed_origins);

    let address = format!("{}:{}", config.server_host, config.server_port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!("Starting server on {}", address);

    serve(listener, router).await?;

    Ok(())
}
