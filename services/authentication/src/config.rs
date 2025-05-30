use anyhow::Context;
use std::env;
use crate::db::DbConfig;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub app_host: String,
    pub app_port: u16,
    pub db_config: DbConfig,
}

pub async fn load_config() -> anyhow::Result<AppConfig> {
    tracing::debug!("Loading application configuration...");
    dotenvy::dotenv().ok(); 

    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable must be set")?;

    let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

    let app_port_str = env::var("APP_PORT").unwrap_or_else(|_| "3000".to_string());
    let app_port: u16 = app_port_str
        .parse()
        .context(format!("Invalid APP_PORT value: '{}'. Must be a valid u16 port number.", app_port_str))?;
    
    let db_c = DbConfig {
        database_url,
        max_connections: env::var("DB_MAX_CONNECTIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(DbConfig::default().max_connections),
        min_connections: env::var("DB_MIN_CONNECTIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(DbConfig::default().min_connections),
        acquire_timeout_seconds: env::var("DB_ACQUIRE_TIMEOUT_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(DbConfig::default().acquire_timeout_seconds),
        idle_timeout_seconds: env::var("DB_IDLE_TIMEOUT_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(DbConfig::default().idle_timeout_seconds),
        max_lifetime_seconds: env::var("DB_MAX_LIFETIME_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(DbConfig::default().max_lifetime_seconds),
    };

    tracing::info!("Application configuration loaded successfully.");
    Ok(AppConfig {
        app_host,
        app_port,
        db_config: db_c,
    })
}
