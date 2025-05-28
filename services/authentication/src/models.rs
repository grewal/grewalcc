use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::{Validate, ValidationError};

// Pre-compiled regex using once_cell
static USERNAME_CHARACTER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_]+$").unwrap());

fn validate_username_characters(username: &str) -> Result<(), ValidationError> {
    if USERNAME_CHARACTER_REGEX.is_match(username) {
        Ok(())
    } else {
        let mut err = ValidationError::new("regex");
        err.message = Some("Username can only contain alphanumeric characters and underscores.".into());
        Err(err)
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct NewUserRequest {
    #[validate(
        length(min = 3, max = 32, message = "Username must be between 3 and 32 characters."),
        custom(function = "crate::models::validate_username_characters")
    )]
    pub username: String,
    #[validate(email(message = "A valid email address is required."))]
    pub email: String,

    #[validate(length(min = 8, max = 128, message = "Password must be between 8 and 128 characters."))]
    pub password: String,
}

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

impl User {
    pub fn get_roles_vec(&self) -> Vec<String> {
        self.roles
            .as_ref()
            .and_then(|json_val| serde_json::from_value(json_val.clone()).ok())
            .unwrap_or_else(Vec::new)
    }
}

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
