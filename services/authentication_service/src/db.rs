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

        let roles_str = get_field("roles").unwrap_or_else(|_| "user".to_string());
        let roles: Vec<String> = roles_str.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        
        let created_at_str = get_field("created_at")?;
        let updated_at_str = map.get("updated_at").cloned().unwrap_or_else(|| created_at_str.clone());

        Ok(User {
            id: Uuid::parse_str(&get_field("user_id")?).map_err(|_| AppError::TypeConversionError("Invalid UUID format for user_id".to_string()))?,
            username: get_field("username")?,
            email: get_field("email")?,
            hashed_password: SecretString::new(get_field("password_hash")?),
            // CORRECTED: The User model expects Option<serde_json::Value>, so we convert the Vec<String>
            roles: Some(serde_json::Value::Array(
                roles.into_iter().map(serde_json::Value::String).collect()
            )),
            created_at: DateTime::parse_from_rfc3339(&created_at_str).map_err(|_| AppError::TypeConversionError("Invalid created_at format".to_string()))?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at_str).map_err(|_| AppError::TypeConversionError("Invalid updated_at format".to_string()))?.with_timezone(&Utc),
        })
    }
}

pub async fn get_user_by_username_or_email(client: &redis::Client, username_or_email: &str) -> Result<Option<User>, AppError> {
    let mut con = client.get_multiplexed_async_connection().await?;
    
    let lookup_key = if username_or_email.contains('@') {
        format!("user:email:{}", username_or_email.to_lowercase())
    } else {
        format!("user:username:{}", username_or_email.to_lowercase())
    };

    let user_id_str: Option<String> = con.get(lookup_key).await?;
    match user_id_str {
        Some(id_str) => {
            let user_uuid = Uuid::parse_str(&id_str).map_err(|_| AppError::TypeConversionError("Invalid UUID format in index".into()))?;
            get_user_by_id(client, user_uuid).await
        }
        None => Ok(None),
    }
}

pub async fn get_user_by_id(client: &redis::Client, user_id: Uuid) -> Result<Option<User>, AppError> {
    let mut con = client.get_multiplexed_async_connection().await?;
    let user_key = format!("user:{}", user_id);

    let redis_user: UserFromRedis = con.hgetall(user_key).await?;
    if redis_user.0.is_empty() {
        return Ok(None);
    }

    let user = User::try_from(redis_user)?;
    Ok(Some(user))
}
