use chrono::{DateTime, Utc};
use secrecy::SecretString; // <-- ADDED
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::Validate;

// --- Request Structs ---
#[derive(Debug, Deserialize, Validate)]
pub struct NewUserRequest {
    #[validate(length(min = 3, max = 30, message = "Username must be between 3 and 30 characters."))]
    pub username: String,
    #[validate(email(message = "Invalid email format."))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long."))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginUserRequest {
    #[validate(length(min = 1, message = "Username or email cannot be empty."))]
    pub username_or_email: String,
    #[validate(length(min = 1, message = "Password cannot be empty."))]
    pub password: String,
}

// --- Database Model Struct ---
#[derive(Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub hashed_password: SecretString,
    pub roles: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
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

#[derive(Debug, Serialize)]
pub struct LoginSuccessResponse {
    pub message: String,
    pub access_token: String,
    pub user: UserResponse,
}

// --- JWT Claims Struct ---
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    // Standard claims
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    // Custom private claims
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub username: String,
    pub email: String,
}
