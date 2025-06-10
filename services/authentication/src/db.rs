use crate::errors::AppError;
use crate::models::User;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use serde_json::Value as JsonValue;

// --- DbConfig & create_db_pool ---
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
            acquire_timeout_seconds: 10,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
        }
    }
}

pub async fn create_db_pool(config: &DbConfig) -> Result<PgPool, AppError> {
    tracing::info!(
        database_url = %config.database_url,
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
        .map_err(|e| {
            tracing::error!(error.cause_chain = ?e, "Failed to create PostgreSQL connection pool");
            AppError::DatabaseConnectionFailed(e.to_string())
        })?;
    tracing::info!("PostgreSQL connection pool successfully created.");
    Ok(pool)
}

#[derive(Debug)]
pub struct NewDbUser {
    pub username: String,
    pub email: String,
    pub hashed_password: String,
    pub roles: Vec<String>,
}

// --- create_user Function ---
pub async fn create_user(pool: &PgPool, new_db_user: NewDbUser) -> Result<User, AppError> {
    tracing::debug!(
        username = %new_db_user.username,
        email = %new_db_user.email,
        "Attempting to create new user in database"
    );

    let roles_for_insert: Option<JsonValue> = if new_db_user.roles.is_empty() {
        None
    } else {
        match serde_json::to_value(&new_db_user.roles) {
            Ok(val) => Some(val),
            Err(e) => {
                tracing::error!("Failed to serialize roles to JSON for insertion: {:?}", e);
                return Err(AppError::SerializationError(format!("Failed to serialize roles: {}", e)));
            }
        }
    };

    let created_user_result = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (username, email, hashed_password, roles)
        VALUES ($1, $2, $3, $4)
        RETURNING
            id,
            username,
            email,
            hashed_password,
            roles, 
            created_at,
            updated_at
        "#,
        new_db_user.username,
        new_db_user.email,
        new_db_user.hashed_password,
        roles_for_insert as Option<JsonValue>
    )
    .fetch_one(pool)
    .await;

    match created_user_result {
        Ok(user) => {
            tracing::info!(user_id = %user.id, username = %user.username, "Successfully created new user");
            Ok(user)
        }
        Err(sqlx_err) => {
            if let Some(db_err) = sqlx_err.as_database_error() {
                if db_err.code() == Some(std::borrow::Cow::from("23505")) {
                    let constraint_name = db_err.constraint().unwrap_or_default().to_lowercase();
                    let (field, message) = if constraint_name.contains("username") {
                        ("username", "A user with this username already exists.")
                    } else if constraint_name.contains("email") {
                        ("email", "A user with this email address already exists.")
                    } else {
                        ("unknown_unique_field", "A conflicting unique value already exists.")
                    };

                    tracing::warn!(
                        "Unique constraint violation during user creation for field '{}' (constraint: {}): {:?}",
                        field, constraint_name, db_err
                    );
                    return Err(AppError::ConflictError {
                        field: field.to_string(),
                        message: message.to_string(),
                    });
                }
            }
            tracing::error!("Database error during user creation: {:?}", sqlx_err);
            Err(AppError::DatabaseQueryError(sqlx_err))
        }
    }
}

// --- Fetch a user by username OR email ---
pub async fn get_user_by_username_or_email(
    pool: &PgPool,
    username_or_email: &str,
) -> Result<Option<User>, AppError> {
    tracing::debug!(identifier = %username_or_email, "Attempting to fetch user by username or email");

    let is_email = username_or_email.contains('@');

    let user_result = if is_email {
        sqlx::query_as!(
            User, // User.roles is Option<JsonValue>
            r#"
            SELECT id, username, email, hashed_password, roles, created_at, updated_at
            FROM users
            WHERE lower(email) = lower($1)
            "#,
            username_or_email
        )
        .fetch_optional(pool)
        .await
    } else {
        sqlx::query_as!(
            User, // User.roles is Option<JsonValue>
            r#"
            SELECT id, username, email, hashed_password, roles, created_at, updated_at
            FROM users
            WHERE lower(username) = lower($1)
            "#,
            username_or_email
        )
        .fetch_optional(pool)
        .await
    };

    match user_result {
        Ok(Some(user)) => {
            tracing::info!(user_id = %user.id, "User found for identifier: {}", username_or_email);
            Ok(Some(user))
        }
        Ok(None) => {
            tracing::info!("No user found for identifier: {}", username_or_email);
            Ok(None)
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error while fetching user by identifier: {}", username_or_email);
            Err(AppError::DatabaseQueryError(e))
        }
    }
}
