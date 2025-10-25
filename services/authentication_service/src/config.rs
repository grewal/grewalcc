// src/config.rs

use anyhow::Context;
use secrecy::SecretString;
use std::env;
use std::str::FromStr;
use jsonwebtoken::Algorithm;

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub private_key_pem_pkcs8: SecretString,
    pub public_key_pem_pkcs8: SecretString,
    pub access_token_expires_in_seconds: i64,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub app_host: String,
    pub app_port: u16,
    pub redis_config: RedisConfig,
    pub jwt_config: JwtConfig,
}

pub async fn load_config() -> anyhow::Result<AppConfig> {
    tracing::debug!("Loading application configuration from environment variables and .env file...");
    match dotenvy::dotenv() {
        Ok(path) => tracing::debug!(".env file loaded successfully from: {:?}", path),
        Err(_) => tracing::debug!(".env file not found or failed to load, relying on environment variables."),
    }

    let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let app_port_str = env::var("APP_PORT").unwrap_or_else(|_| "3000".to_string());
    let app_port: u16 = app_port_str.parse().context(format!(
        "Invalid APP_PORT value: '{}'. Must be a valid u16 port number.",
        app_port_str
    ))?;
    tracing::debug!(app_host = %app_host, app_port = app_port, "Application host and port configured.");

    // --- Start of Database Configuration Changes ---
    let redis_url = env::var("REDIS_URL")
        .context("REDIS_URL environment variable must be set")?;
    
    let redis_config = RedisConfig {
        url: SecretString::new(redis_url),
    };
    tracing::debug!("Redis configuration loaded.");
    // --- End of Database Configuration Changes ---

    let raw_jwt_private_key_pem = env::var("AUTH_SERVICE_JWT_PRIVATE_KEY_PEM")
        .context("AUTH_SERVICE_JWT_PRIVATE_KEY_PEM environment variable must be set")?;
    let jwt_private_key_pem_pkcs8 = SecretString::new(raw_jwt_private_key_pem.replace("\\n", "\n"));
    tracing::debug!("AUTH_SERVICE_JWT_PRIVATE_KEY_PEM loaded.");

    let raw_jwt_public_key_pem = env::var("AUTH_SERVICE_JWT_PUBLIC_KEY_PEM")
        .context("AUTH_SERVICE_JWT_PUBLIC_KEY_PEM environment variable must be set")?;
    let jwt_public_key_pem_pkcs8 = SecretString::new(raw_jwt_public_key_pem.replace("\\n", "\n"));
    tracing::debug!("AUTH_SERVICE_JWT_PUBLIC_KEY_PEM loaded.");

    let jwt_access_token_expires_in_seconds_str =
        env::var("AUTH_SERVICE_JWT_ACCESS_TOKEN_EXPIRES_IN_SECONDS")
            .unwrap_or_else(|_| "3600".to_string());
    let jwt_access_token_expires_in_seconds: i64 = jwt_access_token_expires_in_seconds_str
        .parse()
        .context(format!(
            "Invalid AUTH_SERVICE_JWT_ACCESS_TOKEN_EXPIRES_IN_SECONDS value: '{}'. Must be a valid integer.",
            jwt_access_token_expires_in_seconds_str
        ))?;

    let jwt_algorithm_str = env::var("AUTH_SERVICE_JWT_ALGORITHM")
        .unwrap_or_else(|_| "RS256".to_string());
    let jwt_algorithm = Algorithm::from_str(&jwt_algorithm_str).map_err(|e| {
        anyhow::anyhow!(format!(
            "Invalid AUTH_SERVICE_JWT_ALGORITHM: '{}'. Error: {}. Supported algorithms include: HS256, RS256, ES256, etc.",
            jwt_algorithm_str, e
        ))
    })?;
    tracing::debug!(jwt_algorithm = ?jwt_algorithm, access_token_lifetime_sec = jwt_access_token_expires_in_seconds, "JWT parameters configured.");

    let jwt_c = JwtConfig {
        private_key_pem_pkcs8: jwt_private_key_pem_pkcs8,
        public_key_pem_pkcs8: jwt_public_key_pem_pkcs8,
        access_token_expires_in_seconds: jwt_access_token_expires_in_seconds,
        algorithm: jwt_algorithm,
    };

    tracing::info!("Application configuration loaded successfully.");
    Ok(AppConfig {
        app_host,
        app_port,
        redis_config,
        jwt_config: jwt_c,
    })
}
