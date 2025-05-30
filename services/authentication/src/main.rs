// src/main.rs (Your last working version for registration endpoint)
use axum::{
    extract::State, // Used by health_check_handler
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tracing::{error, info, Level, debug}; // Added debug
use tracing_subscriber::{FmtSubscriber, EnvFilter}; // Added EnvFilter

mod config;
mod db;
mod errors;
mod models;
mod services;
mod handlers;

use config::AppConfig;
use errors::AppError;
use crate::handlers::register_user_handler; // This was in your working version

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok(); // Load .env

    let log_level_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,authentication=debug,sqlx=warn".to_string());
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&log_level_str)).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to parse RUST_LOG ('{}'), using default 'info': {}", log_level_str, e);
            EnvFilter::new("info")
        }))
        .json() // Use json for structured logging
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default tracing subscriber");

    info!("Starting authentication service...");

    let app_config = match crate::config::load_config().await {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            error!("Failed to load application configuration: {:?}", e);
            return Err(AppError::ConfigError(format!(
                "Configuration loading failed: {}",
                e
            )));
        }
    };
    info!(version = env!("CARGO_PKG_VERSION"), "Application configuration loaded successfully.");

    let db_pool = match crate::db::create_db_pool(&app_config.db_config).await {
        Ok(pool) => {
            // Success is logged in create_db_pool
            pool
        }
        Err(app_err) => { // app_err is AppError
            error!("Failed to create database connection pool: {:?}", app_err);
            return Err(app_err);
        }
    };

    info!("Applying database migrations...");
    match sqlx::migrate!("./migrations").run(&db_pool).await {
        Ok(_) => info!("Database migrations applied successfully."),
        Err(e) => {
            error!("Failed to apply database migrations: {:?}", e);
            return Err(AppError::InternalServerError(format!(
                "Database migration failed: {}",
                e
            )));
        }
    }
    
    // Test query from your working version
    match sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM users")
        .fetch_one(&db_pool)
        .await
    {
        Ok((count,)) => {
            info!(user_count = count, "Successfully queried users table. Initial user count: {}", count);
        }
        Err(e) => {
            error!("Failed to query users table after migration: {}", e);
        }
    }

    let app_state = Arc::new(AppState {
        db_pool,
        config: Arc::clone(&app_config),
    });

    let app = Router::new()
        .route("/health", get(health_check_handler)) // Using your health_check_handler
        .route("/auth/register", post(register_user_handler))
        .with_state(app_state); // app_state is already Arc here

    let listen_addr_str = format!("{}:{}", app_config.app_host, app_config.app_port);

    let addr: SocketAddr = match listen_addr_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid server address format '{}': {:?}", listen_addr_str, e);
            return Err(AppError::InternalServerError(format!(
                "Invalid server address: {}",
                e
            )));
        }
    };

    info!("Listening on {}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to address {}: {:?}", addr, e);
            return Err(AppError::InternalServerError(format!(
                "Failed to bind server: {}",
                e
            )));
        }
    };

    info!("Authentication service ready and awaiting connections.");
    if let Err(e) = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        error!("Server error: {:?}", e);
        return Err(AppError::InternalServerError(format!(
            "Server execution failed: {}",
            e
        )));
    }

    Ok(())
}

// Your working health_check_handler that takes State
async fn health_check_handler(State(state): State<Arc<AppState>>) -> &'static str {
    debug!(
        db_pool_connections = state.db_pool.size(),
        db_pool_idle = state.db_pool.num_idle(),
        config_app_port = state.config.app_port,
        "Health check endpoint hit"
    );
    "OK"
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl+C, initiating graceful shutdown...")},
        _ = terminate => { info!("Received terminate signal, initiating graceful shutdown...")},
    }
    info!("Shutdown signal received, server will stop accepting new connections.");
}
