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
use uuid::Uuid;
use chrono::Utc;
use tracing::instrument;

// --- User Registration Handler ---
#[instrument(name = "register_user", skip(state, payload))]
pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AppNewUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    tracing::info!(username = %payload.username, email = %payload.email, "Starting user registration");

    payload.validate()?;

    let hashed_password =
        password_service::hash_password(SecretString::new(payload.password)).await?;

    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let created_at_str = now.to_rfc3339();
    let default_roles = "user";

    let mut conn = state.redis_client.get_multiplexed_async_connection().await?;

    let result: String = redis::cmd("FCALL")
        .arg("register_user")
        .arg(2) // Number of KEYS
        .arg(&payload.username)
        .arg(&payload.email)
        .arg(user_id.to_string())
        .arg(hashed_password)
        .arg(&created_at_str)
        .arg(default_roles)
        .query_async(&mut conn)
        .await?;

    match result.as_str() {
        "OK" => {
            let user_response = UserResponse {
                id: user_id,
                username: payload.username,
                email: payload.email,
                roles: vec![default_roles.to_string()],
                created_at: now,
                updated_at: now,
            };
            tracing::info!(user_id = %user_response.id, "User registration successful via Redis Function");
            Ok(Json(user_response))
        }
        "ERR_USERNAME_EXISTS" => {
            tracing::warn!("Registration failed: username already exists.");
            Err(AppError::ConflictError {
                field: "username".to_string(),
                message: "Username already exists.".to_string(),
            })
        }
        "ERR_EMAIL_EXISTS" => {
            tracing::warn!("Registration failed: email already exists.");
            Err(AppError::ConflictError {
                field: "email".to_string(),
                message: "Email already exists.".to_string(),
            })
        }
        _ => {
            tracing::error!("Redis function 'register_user' returned an unexpected value: {}", result);
            Err(AppError::InternalServerError("An unexpected error occurred during registration.".to_string()))
        }
    }
}


// --- User Login Handler ---
#[instrument(name = "login_user", skip(state, payload), fields(identifier = %payload.username_or_email))]
pub async fn login_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginSuccessResponse>, AppError> {
    tracing::info!("Starting login attempt");

    payload.validate()?;

    // CORRECTED LOGIC: Use a clear, explicit match statement for user lookup.
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

    // THE SECURITY FIX IS HERE: This is a "Guard Clause".
    // If the password is not valid, we exit the function immediately.
    if !password_valid {
        tracing::warn!(user_id = %user.id, "Login attempt failed: Incorrect password");
        return Err(AppError::InvalidCredentials(
            "Invalid username/email or password.".to_string(),
        ));
    }

    // This code below is now only reachable if the password was correct.
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
#[instrument(name = "get_current_user", skip_all, fields(user_id = %authenticated_user.user_id))]
pub async fn get_current_user_handler(
    Extension(authenticated_user): Extension<AuthenticatedUser>,
) -> Result<Json<AuthenticatedUser>, AppError> {
    tracing::info!("Serving /auth/me request");
    Ok(Json(authenticated_user))
}
