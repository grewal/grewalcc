use axum::{
    extract::{Request, State},
    http::{header /*, StatusCode // Not strictly needed here if AppError handles status */},
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{errors::AppError, models::Claims, AppState};

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
    pub email: String,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.user_id,
            username: claims.username,
            roles: claims.roles,
            email: claims.email,
        }
    }
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request, // Make request mutable to add extensions
    next: Next,
) -> Result<Response, AppError> {
    debug!("Entering JWT auth middleware");

    let auth_header_val = request.headers().get(header::AUTHORIZATION);

    let token_str = match auth_header_val {
        Some(val) => {
            match val.to_str() {
                Ok(s) if s.starts_with("Bearer ") => &s[7..],
                _ => {
                    warn!("Authorization header present but not a valid Bearer token format.");
                    return Err(AppError::Unauthorized("Invalid Authorization header format.".to_string()));
                }
            }
        }
        None => {
            warn!("Authorization header missing.");
            return Err(AppError::Unauthorized("Authorization header required.".to_string()));
        }
    };
    
    debug!("Extracted token string for verification.");

    match state.token_service.verify_access_token(token_str) {
        Ok(claims) => {
            debug!(user_id = %claims.user_id, "Token verified successfully by middleware");
            let authenticated_user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(authenticated_user);
            Ok(next.run(request).await)
        }
        Err(app_error) => { // verify_access_token already returns a descriptive AppError
            warn!("Token verification failed in middleware: {:?}", app_error);
            Err(app_error)
        }
    }
}
