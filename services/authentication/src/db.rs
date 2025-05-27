// src/db.rs

use anyhow::Context;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

// Configuration for the database pool
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_seconds: 10, // Default time to wait for a connection from pool
            idle_timeout_seconds: 600,  // 10 minutes
            max_lifetime_seconds: 1800, // 30 minutes
        }
    }
}

pub async fn create_db_pool(config: &DbConfig) -> anyhow::Result<PgPool> {
    tracing::info!(
        max_connections = config.max_connections,
        min_connections = config.min_connections,
        acquire_timeout_seconds = config.acquire_timeout_seconds,
        "Initializing PostgreSQL connection pool..."
    );

    let pool_options = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_seconds))
        .idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
        .max_lifetime(Duration::from_secs(config.max_lifetime_seconds));

    let pool = pool_options
        .connect(&config.database_url)
        .await
        .context(format!(
            "Failed to create PostgreSQL connection pool for database_url (host/db check .env)"
        ))?;

    tracing::info!("PostgreSQL connection pool successfully created.");
    Ok(pool)
}
