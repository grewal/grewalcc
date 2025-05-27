// src/services/password_service.rs

use crate::errors::AppError;
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use tracing::error;

const ARGON2_M_COST: u32 = 19 * 1024;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

pub async fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None).map_err(
            |e| {
                error!("Failed to create Argon2 params: {:?}", e);
                AppError::PasswordHashingError(
                    "Failed to configure hashing parameters.".to_string(),
                )
            },
        )?,
    );

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => {
            error!("Password hashing failed: {:?}", e);
            Err(AppError::PasswordHashingError(format!(
                "Could not hash password: {}",
                e
            )))
        }
    }
}

pub async fn verify_password(password: &str, hash_str: &str) -> Result<bool, AppError> {
    let parsed_hash = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse stored password hash: {:?}", e);
            return Err(AppError::InvalidCredentials(
                "Hash format is incorrect.".to_string(),
            ));
        }
    };
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => {
            error!(
                "Password verification failed with an unexpected error: {:?}",
                e
            );
            Err(AppError::InternalServerError(
                "Password verification process failed.".to_string(),
            ))
        }
    }
}
