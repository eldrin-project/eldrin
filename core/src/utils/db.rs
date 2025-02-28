use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use tracing::{info, error};
use std::time::Duration;

/// Creates a database connection pool
pub async fn create_db_pool(database_url: &str) -> Result<Pool<Postgres>, sqlx::Error> {
    info!("Connecting to database...");
    
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;
    
    info!("Database connection established");
    Ok(pool)
}

/// Runs database migrations
pub async fn run_migrations(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    info!("Running database migrations...");
    
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    
    info!("Database migrations completed successfully");
    Ok(())
}