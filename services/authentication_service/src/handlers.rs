// src/handlers.rs

use crate::{
    db,
    errors::AppError,
    middleware::AuthenticatedUser,
    models::{LoginUserRequest, LoginSuccessResponse, UserResponse, NewUserRequest as AppNewUserRequest},
    services::password_service,
    AppState,
};
use axum::{
    extract::{Extension, State},
    Json,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use validator::Validate;

// --- User Registration Handler ---
pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AppNewUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    tracing::info!(username = %payload.username, email = %payload.email, "Received registration request");

    payload.validate()?;

    let hashed_password =
        password_service::hash_password(SecretString::new(payload.password)).await?;

    let default_roles = vec!["user".to_string()];
    let new_db_user = db::NewDbUser {
        username: payload.username,
        email: payload.email,
        hashed_password,
        roles: default_roles,
    };

    let created_user = db::create_user(&state.redis_client, new_db_user).await?;
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

    payload.validate()?;

    let user = match db::get_user_by_username_or_email(&state.redis_client, &payload.username_or_email).await? {
        Some(user) => user,
        None => {
            tracing::warn!("Login attempt failed: User not found for identifier '{}'", payload.username_or_email);
            return Err(AppError::InvalidCredentials(
                "Invalid username/email or password.".to_string(),
            ));
        }
    };

    let password_valid = password_service::verify_password(
        user.hashed_password.expose_secret(),
        SecretString::new(payload.password),
    )
    .await?;

    if !password_valid {
        tracing::warn!("Login attempt failed: Incorrect password for user_id '{}'", user.id);
        return Err(AppError::InvalidCredentials(
            "Invalid username/email or password.".to_string(),
        ));
    }

    let token_service = state.token_service.clone();
    let access_token = token_service.generate_access_token(
        user.id,
        &user.username,
        &user.email,
        &user.get_roles_vec(),
    )?;

    tracing::info!(user_id = %user.id, "User login successful, token generated");

    Ok(Json(LoginSuccessResponse {
        message: "Login successful.".to_string(),
        access_token,
        user: UserResponse::from(&user),
    }))
}

// --- Get Current User Handler (Protected) ---
pub async fn get_current_user_handler(
    Extension(authenticated_user): Extension<AuthenticatedUser>,
) -> Result<Json<AuthenticatedUser>, AppError> {
    tracing::info!(user_id = %authenticated_user.user_id, username = %authenticated_user.username, "Serving /auth/me request for authenticated user");
    Ok(Json(authenticated_user))
}
