// src/main.rs

// External Crate Imports
use anyhow::Context;
use axum::{
    routing::{get, post}, // Added post for future /register
    extract::State,
    Router,
};
use sqlx::PgPool; // Only need PgPool here, options are in db.rs
use std::env;
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

// --- MODULE DECLARATIONS ---
mod config;
mod db;
mod errors;
mod handlers; // Will be used soon
mod kv_store; // Placeholder for now
mod models;   // Will be used soon
mod services; // Placeholder for now
// --- END MODULE DECLARATIONS ---

// --- BRINGING ITEMS INTO SCOPE ---
use config::AppConfig;         // From src/config.rs
use db::create_db_pool;       // From src/db.rs
// use errors::AppError;      // We'll use this in handlers, main returns anyhow::Result for now
// use models::{RegisterUserRequest, UserRegisteredResponse}; // For handlers later
// use handlers::handle_register; // For handlers later

// Application state that can be shared with Axum handlers
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: AppConfig,
    // Future additions:
    // pub consul_client: consulrs::Client,
    // pub redis_client: redis::Client, // Or a deadpool_redis::Pool
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load .env file if it exists (for local development)
    dotenvy::dotenv().ok();

    // 2. Initialize Logging (tracing)
    let log_level_str = env::var("RUST_LOG").unwrap_or_else(|_| "info,authentication=debug,sqlx=warn".to_string());
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO) // Default global level
        .with_env_filter(EnvFilter::try_new(&log_level_str).unwrap_or_else(|_| EnvFilter::new("info")))
        .json() // Structured JSON logging
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    tracing::info!("Authentication service starting up...");

    // 3. Load application configuration using the config module
    let app_config = config::load_config().await
        .context("Failed to load application configuration")?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Application configuration loaded."); // Added version

    // 4. Create PostgreSQL Connection Pool using the db module
    tracing::info!(database_url = %app_config.db_config.database_url, "Connecting to database...");
    let db_pool = create_db_pool(&app_config.db_config) // Pass the db_config field from AppConfig
        .await
        .context("Failed to create PostgreSQL connection pool")?;
    // Success message is now inside create_db_pool

    // 5. Run DB Migrations on startup
    tracing::info!("Running database migrations...");
    sqlx::migrate!("./migrations") // Path relative to Cargo.toml
        .run(&db_pool)
        .await
        .context("Failed to run database migrations")?;
    tracing::info!("Database migrations applied successfully.");

    // 6. Perform a relevant test query
    match sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM users")
        .fetch_one(&db_pool)
        .await
    {
        Ok((count,)) => {
            tracing::info!(user_count = count, "Successfully queried users table.");
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to query users table after migration.");
            // Consider more robust error handling or exiting if this critical check fails
        }
    }
    
    // 7. Create AppState instance
    let app_state = AppState { 
        db_pool, 
        config: app_config.clone(), // Clone app_config if it's used elsewhere after moving into AppState
                                   // Or if AppState itself is cloned frequently by Axum.
                                   // Alternatively, wrap AppConfig in Arc if it's large and frequently cloned.
    };

    // 8. Set up Axum Router and HTTP Server
    let app = Router::new()
        .route("/health", get(health_check_handler))
        // Placeholder for registration route - will be added soon:
        // .route("/api/auth/register", post(handlers::handle_register)) 
        .with_state(app_state.clone()); // Axum needs AppState to be Clone

    let listen_addr_str = format!("{}:{}", app_state.config.app_host, app_state.config.app_port);
    let listen_addr: SocketAddr = listen_addr_str
        .parse()
        .context(format!("Invalid listen address format: {}", listen_addr_str))?;

    tracing::info!(address = %listen_addr, "HTTP server listening");

    axum::serve(tokio::net::TcpListener::bind(listen_addr).await?, app.into_make_service())
        .await
        .context("HTTP server failed")?;
        
    Ok(())
}

// Simple health check handler
async fn health_check_handler(State(app_state): State<AppState>) -> &'static str {
    // Example of accessing app_state in a handler, logging DB pool stats
    tracing::debug!(
        db_pool_connections = app_state.db_pool.size(),
        db_pool_idle = app_state.db_pool.num_idle(),
        "Health check endpoint hit"
    );
    "OK"
}
