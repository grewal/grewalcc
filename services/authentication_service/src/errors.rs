// src/errors.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database query failed: {0}")]
    DatabaseQueryError(String),

    #[error("Failed to connect to database: {0}")]
    DatabaseConnectionFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Type conversion error: {0}")]
    TypeConversionError(String),

    #[error("Input validation failed")]
    InputValidationError(#[from] validator::ValidationErrors),

    #[error("Conflict error for field '{field}': {message}")]
    ConflictError { field: String, message: String },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid Credentials: {0}")]
    InvalidCredentials(String),

    #[error("Password Hashing Error: {0}")]
    PasswordHashingError(String),

    #[error("Token Creation Error: {0}")]
    TokenCreationError(String),

    #[error("Username already exists")]
    UsernameAlreadyExists,

    #[error("Email already exists")]
    EmailAlreadyExists,
}

// Helper to convert RedisError to AppError
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::DatabaseQueryError(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_json) = match self {
            AppError::InputValidationError(errors) => {
                let messages = errors
                    .field_errors()
                    .into_iter()
                    .map(|(field, errs)| {
                        let field_messages: Vec<String> = errs
                            .iter()
                            .map(|e| e.message.as_ref().unwrap_or(&"Invalid value".into()).to_string())
                            .collect();
                        (field, field_messages)
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                (StatusCode::UNPROCESSABLE_ENTITY, json!({ "errors": messages }))
            }
            AppError::ConflictError { field, message } => {
                (StatusCode::CONFLICT, json!({ "field": field, "message": message }))
            }
            AppError::UsernameAlreadyExists => (
                StatusCode::CONFLICT,
                json!({ "field": "username", "message": "Username already exists" }),
            ),
            AppError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                json!({ "field": "email", "message": "Email already exists" }),
            ),
            AppError::InvalidCredentials(message)
            | AppError::Unauthorized(message)
            | AppError::TokenCreationError(message) => {
                (StatusCode::UNAUTHORIZED, json!({ "error": message }))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": self.to_string() }),
            ),
        };

        (status, Json(error_json)).into_response()
    }
}
