use sqlx::migrate::Migrator;
use sqlx::postgres::PgPool;
use std::path::Path;

pub async fn run_pending_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(pool).await
}

