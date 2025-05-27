use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

// --- Request Structs ---

#[derive(Debug, Deserialize)]
pub struct NewUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

// --- Database Model Struct ---

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub roles: SqlxJson<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// --- Response Structs ---

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>, // Note: Vec<String>, not SqlxJson for serialization
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// --- Helper for creating UserResponse from User ---
impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            roles: user.roles.0, // Extract Vec<String> from SqlxJson wrapper
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}
