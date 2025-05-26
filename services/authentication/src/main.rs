use anyhow::Context;
use axum::{routing::get, Router};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// Application state that can be shared with Axum handlers if needed later
#[derive(Clone)]
struct AppState {
    db_pool: PgPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // 2. Initialize Logging (tracing)
    // Construct a subscriber that filters messages based on the RUST_LOG environment variable.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO) // Default level if RUST_LOG is not set
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // Respect RUST_LOG
        .json() // Log in JSON format for better machine readability (optional, can be .pretty() for dev)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    tracing::info!("Authentication service starting up...");

    // 3. Load DATABASE_URL from environment
    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable must be set")?;
    tracing::info!("Connecting to database...");

    // 4. Create PostgreSQL Connection Pool
    let db_pool = PgPoolOptions::new()
        .max_connections(5) // Configure max connections in the pool
        .connect(&database_url)
        .await
        .context("Failed to create PostgreSQL connection pool")?;
    tracing::info!("PostgreSQL connection pool created successfully.");

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
            tracing::info!("Successfully queried users table. Initial user count: {}", count);
        }
        Err(e) => {
            tracing::error!("Failed to query users table after migration: {}", e);
        }
    }
    
    // Create an AppState instance (will be useful for handlers later)
    let app_state = AppState { db_pool };


    // 7. Set up Axum Router and HTTP Server
    let app = Router::new()
        .route("/health", get(health_check_handler))
        .with_state(app_state); // Makes AppState available to handlers

    let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let app_port_str = env::var("APP_PORT").unwrap_or_else(|_| "3000".to_string());
    let app_port: u16 = app_port_str
        .parse()
        .context(format!("Invalid APP_PORT value: {}", app_port_str))?;

    let addr_str = format!("{}:{}", app_host, app_port);
    let addr: SocketAddr = addr_str
        .parse()
        .context(format!("Invalid listen address format: {}", addr_str))?;

    tracing::info!("HTTP server listening on {}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app.into_make_service())
        .await
        .context("HTTP server failed")?;
        
    Ok(())
}

// health check handler
async fn health_check_handler() -> &'static str {
    tracing::debug!("Health check endpoint hit");
    "OK"
}
