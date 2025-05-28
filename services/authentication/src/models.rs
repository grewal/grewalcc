use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
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
    pub hashed_password: String,
    pub roles: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Helper methods on User to get/set roles as Vec<String>
impl User {
    // Helper to get roles as Vec<String>, handles None or malformed JSON
    pub fn get_roles_vec(&self) -> Vec<String> {
        self.roles
            .as_ref()
            .and_then(|json_val| serde_json::from_value(json_val.clone()).ok())
            .unwrap_or_else(Vec::new)
    }
}


// --- Response Structs ---
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&User> for UserResponse {
    fn from(user: &User) -> Self {
        UserResponse {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            roles: user.get_roles_vec(),
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}
