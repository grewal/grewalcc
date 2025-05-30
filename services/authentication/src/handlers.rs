use crate::{
    config::JwtConfig,
    db,
    errors::AppError,
    models::{LoginUserRequest, LoginSuccessResponse, UserResponse, NewUserRequest as AppNewUserRequest},
    services::{password_service, token_service},
    AppState,
};
use axum::{extract::State, Json};
use secrecy::SecretString;
use std::sync::Arc;
use validator::Validate;

pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AppNewUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    tracing::info!(username = %payload.username, email = %payload.email, "Received registration request");

    payload.validate().map_err(|e| {
        let mut errors = std::collections::HashMap::new();
        for (field, field_errors) in e.field_errors() {
            let messages: Vec<String> = field_errors.iter().map(|fe| fe.message.as_ref().unwrap_or(&"Invalid input".into()).to_string()).collect();
            errors.insert(field.to_string(), messages.join(", "));
        }
        AppError::InputValidationError(errors)
    })?;

    let hashed_password =
        password_service::hash_password(SecretString::new(payload.password)).await?;

    let default_roles = vec!["user".to_string()];
    let new_db_user = db::NewDbUser {
        username: payload.username,
        email: payload.email,
        hashed_password,
        roles: default_roles,
    };

    let created_user = db::create_user(&state.db_pool, new_db_user).await?;
    let user_response = UserResponse::from(&created_user);

    tracing::info!(user_id = %user_response.id, "User registration successful");
    Ok(Json(user_response))
}


// --- User Login Handler ---
pub async fn login_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginSuccessResponse>, AppError> {
    tracing::info!(identifier = %payload.username_or_email, "Received login request");

    payload.validate().map_err(|e| {
        let mut errors = std::collections::HashMap::new();
        for (field, field_errors) in e.field_errors() {
            let messages: Vec<String> = field_errors.iter().map(|fe| fe.message.as_ref().unwrap_or(&"Invalid input".into()).to_string()).collect();
            errors.insert(field.to_string(), messages.join(", "));
        }
        AppError::InputValidationError(errors)
    })?;

    let user = match db::get_user_by_username_or_email(&state.db_pool, &payload.username_or_email).await? {
        Some(user) => user,
        None => {
            tracing::warn!("Login attempt failed: User not found for identifier '{}'", payload.username_or_email);
            return Err(AppError::InvalidCredentials(
                "Invalid username/email or password.".to_string(),
            ));
        }
    };

    let password_valid = password_service::verify_password(
        &user.hashed_password,
        SecretString::new(payload.password),
    )
    .await?;

    if !password_valid {
        tracing::warn!("Login attempt failed: Incorrect password for user_id '{}'", user.id);
        return Err(AppError::InvalidCredentials(
            "Invalid username/email or password.".to_string(),
        ));
    }

    let jwt_config_clone: JwtConfig = state.config.jwt_config.clone();
    let temp_token_service = token_service::TokenService::new(Arc::new(jwt_config_clone))?;

    let access_token = temp_token_service.generate_access_token(
        user.id,
        &user.username,
        &user.get_roles_vec(),
    )?;

    tracing::info!(user_id = %user.id, "User login successful, token generated");

    Ok(Json(LoginSuccessResponse {
        message: "Login successful.".to_string(),
        access_token,
        user: UserResponse::from(&user),
    }))
}
