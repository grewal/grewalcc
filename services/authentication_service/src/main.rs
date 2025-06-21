use axum::{
    extract::State,
    routing::{get, post},
    Router,
    middleware as axum_middleware,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tracing::{error, info, Level, debug};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

mod config;
mod db;
mod errors;
mod handlers;
mod kv_store;
mod models;
mod services;
mod middleware;

use config::AppConfig;
use errors::AppError;
use crate::handlers::{register_user_handler, login_user_handler, get_current_user_handler};
use crate::services::token_service::TokenService;
use crate::middleware::auth_middleware as app_auth_middleware;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub config: Arc<AppConfig>,
    pub token_service: Arc<TokenService>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();

    let log_level_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,authentication=debug,sqlx=warn,jsonwebtoken=debug".to_string());
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&log_level_str)).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to parse RUST_LOG ('{}'), using default 'info': {}", log_level_str, e);
            EnvFilter::new("info")
        }))
        .json()
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

    info!(database_url = %app_config.db_config.database_url, "Connecting to database...");
    let db_pool = crate::db::create_db_pool(&app_config.db_config).await?;
    
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

    let cloned_jwt_config: config::JwtConfig = app_config.jwt_config.clone();
    let jwt_config_arc_for_service: Arc<config::JwtConfig> = Arc::new(cloned_jwt_config);
    let token_service = Arc::new(TokenService::new(jwt_config_arc_for_service)?);
    info!("TokenService initialized successfully.");

    let app_state = Arc::new(AppState {
        db_pool,
        config: Arc::clone(&app_config),
        token_service: Arc::clone(&token_service),
    });

    // Define protected routes that need AppState for the middleware
    let protected_routes = Router::new()
        .route("/me", get(get_current_user_handler))
        // Add other protected routes here later
        .route_layer(axum_middleware::from_fn_with_state(Arc::clone(&app_state), app_auth_middleware));

    // Define public routes
    let public_routes = Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler));

    // Combine routers
    let app = Router::new()
        .route("/health", get(health_check_handler)) // Health check is public
        .nest("/auth", public_routes.merge(protected_routes)) // Nest all /auth routes
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
