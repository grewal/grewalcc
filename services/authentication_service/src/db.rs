// src/db.rs
use crate::config::RedisConfig;
use crate::errors::AppError;
use crate::models::User;
use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use std::collections::HashMap;

pub async fn create_redis_client(config: &RedisConfig) -> Result<redis::Client, AppError> {
    tracing::info!("Initializing Redis client...");
    let client = redis::Client::open(config.url.expose_secret().as_str()).map_err(|e| {
        tracing::error!(error.cause_chain = ?e, "Failed to create Redis client");
        AppError::DatabaseConnectionFailed(e.to_string())
    })?;
    tracing::info!("Redis client created. A connection will be established on first use.");
    Ok(client)
}

#[derive(Debug)]
pub struct NewDbUser {
    pub username: String,
    pub email: String,
    pub hashed_password: String,
    pub roles: Vec<String>,
}

struct UserFromRedis(HashMap<String, String>);

impl FromRedisValue for UserFromRedis {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        let map: HashMap<String, String> = redis::from_redis_value(v)?;
        Ok(UserFromRedis(map))
    }
}

impl TryFrom<UserFromRedis> for User {
    type Error = AppError;

    fn try_from(redis_data: UserFromRedis) -> Result<Self, Self::Error> {
        let map = redis_data.0;
        let get_field = |key: &str| -> Result<String, AppError> {
            map.get(key).cloned().ok_or_else(|| AppError::TypeConversionError(format!("Missing field '{}' in Redis hash", key)))
        };

        Ok(User {
            id: Uuid::parse_str(&get_field("id")?).map_err(|_| AppError::TypeConversionError("Invalid UUID format for id".to_string()))?,
            username: get_field("username")?,
            email: get_field("email")?,
            hashed_password: SecretString::new(get_field("hashed_password")?), // Correctly wrapped
            roles: match map.get("roles") {
                Some(roles_json) if !roles_json.is_empty() => Some(serde_json::from_str(roles_json).map_err(|_| AppError::TypeConversionError("Invalid JSON for roles".to_string()))?),
                _ => None,
            },
            created_at: DateTime::parse_from_rfc3339(&get_field("created_at")?).map_err(|_| AppError::TypeConversionError("Invalid created_at format".to_string()))?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&get_field("updated_at")?).map_err(|_| AppError::TypeConversionError("Invalid updated_at format".to_string()))?.with_timezone(&Utc),
        })
    }
}

pub async fn create_user(client: &redis::Client, new_db_user: NewDbUser) -> Result<User, AppError> {
    let mut con = client.get_multiplexed_async_connection().await.map_err(AppError::DatabaseQueryError)?;
    let user_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let user_key = format!("user:{}", user_id);
    let username_key = format!("username:{}", new_db_user.username.to_lowercase());
    let email_key = format!("email:{}", new_db_user.email.to_lowercase());

    let (username_exists, email_exists): (bool, bool) = redis::pipe()
        .exists(&username_key).exists(&email_key).query_async(&mut con).await?;

    if username_exists { return Err(AppError::ConflictError { field: "username".into(), message: "Username already exists.".into() }); }
    if email_exists { return Err(AppError::ConflictError { field: "email".into(), message: "Email already exists.".into() }); }

    let roles_json = serde_json::to_string(&new_db_user.roles).map_err(|e| AppError::SerializationError(e.to_string()))?;

    let user_data = &[
        ("id", user_id.to_string()), ("username", new_db_user.username), ("email", new_db_user.email),
        ("hashed_password", new_db_user.hashed_password), ("roles", roles_json),
        ("created_at", now.clone()), ("updated_at", now),
    ];

    redis::pipe().atomic()
        .hset_multiple(&user_key, user_data)
        .set(&username_key, user_id.to_string())
        .set(&email_key, user_id.to_string())
        .query_async::<()>(&mut con).await?;
    
    get_user_by_id(client, user_id).await?.ok_or_else(|| AppError::InternalServerError("Failed to retrieve user after creation".into()))
}

pub async fn get_user_by_username_or_email(client: &redis::Client, username_or_email: &str) -> Result<Option<User>, AppError> {
    let mut con = client.get_multiplexed_async_connection().await.map_err(AppError::DatabaseQueryError)?;
    let lookup_key = if username_or_email.contains('@') {
        format!("email:{}", username_or_email.to_lowercase())
    } else {
        format!("username:{}", username_or_email.to_lowercase())
    };

    let user_id: Option<String> = con.get(lookup_key).await?;
    match user_id {
        Some(id_str) => {
            let user_id_uuid = Uuid::parse_str(&id_str).map_err(|_| AppError::TypeConversionError("Invalid UUID format in index".into()))?;
            get_user_by_id(client, user_id_uuid).await
        }
        None => Ok(None),
    }
}

pub async fn get_user_by_id(client: &redis::Client, user_id: Uuid) -> Result<Option<User>, AppError> {
    let mut con = client.get_multiplexed_async_connection().await.map_err(AppError::DatabaseQueryError)?;
    let user_key = format!("user:{}", user_id);

    let redis_user: UserFromRedis = con.hgetall(user_key).await?;
    if redis_user.0.is_empty() {
        return Ok(None);
    }
    
    let user = User::try_from(redis_user)?;
    Ok(Some(user))
}
