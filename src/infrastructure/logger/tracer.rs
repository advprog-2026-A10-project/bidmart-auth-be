use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracer() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bidmart_auth_be=debug,tower=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
