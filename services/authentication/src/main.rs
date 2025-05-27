// services/authentication/src/main.rs

use axum::{routing::get, Router};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

// Import modules from the current crate
mod config;
mod db;
mod errors;
mod models;
mod services;

// Now we can use items from these modules
use config::AppConfig;
// use db::DbConfig;
use errors::AppError;

// Define the application state
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> { // AppError is now in scope
    // Initialize tracing (logging)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default tracing subscriber");

    info!("Starting authentication service..."); // info! macro is now in scope

    // Load application configuration
    let app_config_result = config::load_config().await; // config module is declared
    let app_config = match app_config_result {
        Ok(cfg) => Arc::new(cfg), // Arc is now in scope
        Err(e) => {
            error!("Failed to load application configuration: {:?}", e); // error! macro is now in scope
            return Err(AppError::ConfigError(format!(
                "Configuration loading failed: {}",
                e
            )));
        }
    };
    info!("Configuration loaded successfully.");

    // Create database connection pool
    let db_pool = match db::create_db_pool(&app_config.db_config).await { // db module is declared
        Ok(pool) => {
            info!("Database connection pool created successfully.");
            pool
        }
        Err(app_err) => {
            error!("Failed to create database connection pool: {:?}", app_err);
            return Err(app_err);
        }
    };

    // Run database migrations
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

    // Create the application state
    let app_state = Arc::new(AppState { // AppState is defined above, Arc is in scope
        db_pool,
        config: Arc::clone(&app_config), // Arc is in scope
    });

    // Define application routes
    let app = Router::new() // Router is now in scope
        .route("/health", get(|| async { "OK" })) // get is now in scope
        .with_state(app_state);

    // Determine listen address from AppConfig
    let listen_addr_str = format!("{}:{}", app_config.app_host, app_config.app_port);

    let addr: SocketAddr = match listen_addr_str.parse() { // SocketAddr is now in scope
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

    // Start the Axum server
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

// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c() // signal is now in scope (from tokio::signal)
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate()) // signal::unix is now in scope
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
