use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracer() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,bidmart_auth_be=debug,tower_http=info,sqlx=warn,axum=info")
    });

    let log_format = std::env::var("APP_LOG_FORMAT")
        .ok()
        .map(|format| format.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "plain".to_string());

    let subscriber = tracing_subscriber::registry().with(env_filter);
    if log_format == "json" {
        subscriber
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_target(true),
            )
            .init();
        return;
    }

    subscriber
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_names(true)
                .with_line_number(true),
        )
        .init();
}
