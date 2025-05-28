use crate::{
    db::{create_user, NewDbUser},
    errors::AppError,
    models::{NewUserRequest, UserResponse},
    services::password_service,
    AppState,
};
use axum::{extract::State, Json};
use secrecy::SecretString;
use std::sync::Arc;
use tracing::{info, warn, debug};

// --- User Registration Handler ---
pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NewUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    info!(username = %payload.username, email = %payload.email, "Received registration request");

    // --- Basic Input Validation ---
    if payload.username.trim().is_empty() {
        warn!("Registration attempt with empty username.");
        // Create a HashMap for the error details
        let mut errors = std::collections::HashMap::new();
        errors.insert("username".to_string(), "Username cannot be empty.".to_string());
        return Err(AppError::InputValidationError(errors));
    }
    if payload.username.len() < 3 { // Example: minimum username length
        warn!("Registration attempt with username too short: {}", payload.username);
        let mut errors = std::collections::HashMap::new();
        errors.insert("username".to_string(), "Username must be at least 3 characters long.".to_string());
        return Err(AppError::InputValidationError(errors));
    }
    if payload.email.trim().is_empty() || !payload.email.contains('@') { // Basic email check
        warn!("Registration attempt with invalid email: {}", payload.email);
        let mut errors = std::collections::HashMap::new();
        errors.insert("email".to_string(), "A valid email address is required.".to_string());
        return Err(AppError::InputValidationError(errors));
    }
    if payload.password.len() < 8 { // Basic password length check
        warn!("Registration attempt with password too short.");
        let mut errors = std::collections::HashMap::new();
        errors.insert("password".to_string(), "Password must be at least 8 characters long.".to_string());
        return Err(AppError::InputValidationError(errors));
    }
    // --- End Basic Input Validation ---

    debug!("Input validation passed for registration request.");

    // Hash the password using the password_service
    // Convert payload.password (String) to SecretString
    let secret_password = SecretString::new(payload.password);
    let hashed_password = match password_service::hash_password(secret_password).await {
        Ok(hash) => hash,
        Err(e) => {
            // error will be converted to a 500 by AppError::IntoResponse.
            return Err(e);
        }
    };
    debug!("Password hashing successful for registration.");

    // Prepare user data for database insertion
    // New users get a default "user" role.
    let default_roles = vec!["user".to_string()];
    let new_db_user = NewDbUser {
        username: payload.username,
        email: payload.email,
        hashed_password,
        roles: default_roles,
    };

    debug!("Attempting to create user in database...");
    // Create the user in the database using the db module function
    let created_user = match create_user(&state.db_pool, new_db_user).await {
        Ok(user) => user,
        Err(e) => {
            return Err(e);
        }
    };
    info!(user_id = %created_user.id, "User successfully created in database.");

    // Convert the database User model to the API UserResponse model
    let user_response = UserResponse::from(&created_user);

    // Return the successful response
    Ok(Json(user_response))
}
