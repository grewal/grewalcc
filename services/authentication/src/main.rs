use axum::{routing::get, Router};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod db;
mod errors;
mod models;
mod services;

use config::AppConfig;
use errors::AppError;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default tracing subscriber");

    info!("Starting authentication service...");

    let app_config_result = crate::config::load_config().await;
    let app_config = match app_config_result {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            error!("Failed to load application configuration: {:?}", e);
            return Err(AppError::ConfigError(format!(
                "Configuration loading failed: {}",
                e
            )));
        }
    };
    info!("Configuration loaded successfully.");

    let db_pool = match crate::db::create_db_pool(&app_config.db_config).await {
        Ok(pool) => {
            info!("Database connection pool created successfully.");
            pool
        }
        Err(app_err) => {
            error!("Failed to create database connection pool: {:?}", app_err);
            return Err(app_err);
        }
    };

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

    let app_state = Arc::new(AppState {
        db_pool,
        config: Arc::clone(&app_config),
    });

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .with_state(app_state);

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
        _ = ctrl_c => { info!("Received Ctrl+C, shutting down.")},
        _ = terminate => { info!("Received terminate signal, shutting down.")},
    }
}
