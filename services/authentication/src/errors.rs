// src/errors.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::collections::HashMap;

// --- Generic Error Response Struct ---
// struct will be serialized into JSON for error responses
#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

// --- Application Error Enum ---
// This enum defines the different kinds of errors application can encounter.
#[derive(Debug)] // Implement Debug for logging purposes
pub enum AppError {
    // Errors related to database operations
    DatabaseQueryError(sqlx::Error),
    // Errors during password hashing
    PasswordHashingError(String), // Include a message for context
    // Errors from input validation
    InputValidationError(HashMap<String, String>), // Key is field name, Value is error message
    // Errors when a user or resource conflicts (e.g., username/email already exists)
    ConflictError { field: String, message: String },
    // Errors from JWT operations (e.g. creation, signing)
    TokenCreationError(String),
    // Errors for unauthorized access attempts (though primary JWT validation is by Envoy)
    Unauthorized(String),
    // Generic internal server error
    InternalServerError(String),
    // Errors from configuration loading
    ConfigError(String),
    // Errors from external service calls (e.g. Consul, Redis)
    ExternalServiceError{ service_name: String, details: String }
}

// Implement IntoResponse for AppError
// This tells Axum how to convert our AppError enum into an HTTP response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, details, field) = match self {
            AppError::DatabaseQueryError(db_err) => {
                tracing::error!(error.cause_chain = ?db_err, "Database query error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A database error occurred.".to_string(),
                    None,
                    None,
                )
            }
            AppError::PasswordHashingError(msg) => {
                tracing::error!("Password hashing error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred during authentication processing.".to_string(),
                    None,
                    None,
                )
            }
            AppError::InputValidationError(validation_errors) => {
                tracing::warn!(errors = ?validation_errors, "Input validation failed");
                (
                    StatusCode::BAD_REQUEST,
                    "Input validation failed. Please check the provided data.".to_string(),
                    Some(validation_errors),
                    None,
                )
            }
            AppError::ConflictError { field, message } => {
                tracing::warn!("Conflict error: field={}, message={}", field, message);
                (
                    StatusCode::CONFLICT, 
                    message, 
                    None, 
                    Some(field)
                )
            }
            AppError::TokenCreationError(msg) => {
                tracing::error!("Token creation error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not process authentication request due to a token error.".to_string(),
                    None,
                    None,
                )
            }
            AppError::Unauthorized(msg) => {
                tracing::warn!("Unauthorized access attempt: {}", msg);
                (
                    StatusCode::UNAUTHORIZED,
                    msg, // Directly use the message for unauthorized
                    None,
                    None
                )
            }
            AppError::InternalServerError(msg) => {
                tracing::error!("Internal server error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An unexpected internal server error occurred.".to_string(),
                    None,
                    None
                )
            }
            AppError::ConfigError(msg) => {
                tracing::error!("Configuration error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR, // Config errors are server-side
                    "Server configuration error.".to_string(),
                    None,
                    None
                )
            }
            AppError::ExternalServiceError{ service_name, details } => {
                tracing::error!("External service error: service={}, details={}", service_name, details);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("A problem occurred while communicating with an external service ({}).", service_name),
                    None,
                    None
                )
            }
        };

        let body = Json(ErrorResponse {
            error: error_message,
            details,
            field,
        });

        (status, body).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::DatabaseQueryError(e) => write!(f, "Database error: {}", e),
            AppError::PasswordHashingError(msg) => write!(f, "Password hashing error: {}", msg),
            AppError::InputValidationError(details) => write!(f, "Input validation failed: {:?}", details),
            AppError::ConflictError { field, message } => write!(f, "Conflict on field '{}': {}", field, message),
            AppError::TokenCreationError(msg) => write!(f, "Token creation error: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
            AppError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            AppError::ExternalServiceError { service_name, details } => write!(f, "External service error with {}: {}", service_name, details),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::DatabaseQueryError(e) => Some(e),
            _ => None,
        }
    }
}
