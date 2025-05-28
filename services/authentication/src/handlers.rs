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
use validator::Validate;

// --- User Registration Handler ---
pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NewUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    info!(username = %payload.username, email = %payload.email, "Received registration request");

    if let Err(validation_errors) = payload.validate() {
        warn!("Input validation failed for registration request: {:?}", validation_errors);
        let mut error_map = std::collections::HashMap::new();
        for (field, errors) in validation_errors.field_errors() {
            if let Some(first_error) = errors.first() {
                let message = first_error.message.as_ref().map(|s| s.to_string())
                    .unwrap_or_else(|| first_error.code.to_string());
                error_map.insert(field.to_string(), message);
            }
        }
        return Err(AppError::InputValidationError(error_map));
    }

    debug!("Input validation passed for registration request.");

    let secret_password = SecretString::new(payload.password);
    let hashed_password = match password_service::hash_password(secret_password).await {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    debug!("Password hashing successful for registration.");

    let default_roles = vec!["user".to_string()];
    let new_db_user = NewDbUser {
        username: payload.username,
        email: payload.email,
        hashed_password,
        roles: default_roles,
    };

    debug!("Attempting to create user in database...");
    let created_user = match create_user(&state.db_pool, new_db_user).await {
        Ok(user) => user,
        Err(e) => return Err(e),
    };
    info!(user_id = %created_user.id, "User successfully created in database.");

    let user_response = UserResponse::from(&created_user);
    Ok(Json(user_response))
}
