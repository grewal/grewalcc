// src/services/password_service.rs
use crate::errors::AppError;
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2, Params,
};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, error, info, warn};

const ARGON2_M_COST: u32 = 19 * 1024;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

pub async fn hash_password(password: SecretString) -> Result<String, AppError> {
    debug!("Attempting to hash password.");
    let hashed_password_string = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|e| {
            error!("Failed to create Argon2 params: {:?}", e);
            AppError::PasswordHashingError("Failed to configure hashing parameters.".to_string())
        })?;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| {
                error!("Password hashing failed: {:?}", e);
                AppError::PasswordHashingError(format!("Could not hash password: {}", e))
            })
    })
    .await
    .map_err(|e| {
        error!("Password hashing task panicked or was cancelled: {:?}", e);
        AppError::InternalServerError("Password hashing process failed unexpectedly.".to_string())
    })??;
    info!("Password hashed successfully.");
    Ok(hashed_password_string)
}

// CORRECTED VERSION
pub async fn verify_password(password_hash_str: &str, password_to_verify: SecretString) -> Result<bool, AppError> {
    debug!("Attempting to verify password.");

    let owned_password_hash_str = password_hash_str.to_string();

    // The logic is now moved entirely inside the blocking task for clarity.
    let verification_result = tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&owned_password_hash_str) {
            Ok(h) => h,
            Err(e) => {
                // This is a server-side issue (bad hash in DB), not a password mismatch.
                error!("Failed to parse stored password hash: {:?}", e);
                return Err(AppError::InternalServerError("Stored password hash is invalid.".to_string()));
            }
        };

        match Argon2::default().verify_password(password_to_verify.expose_secret().as_bytes(), &parsed_hash) {
            Ok(_) => {
                info!("Password verification successful.");
                Ok(true) // Password is correct
            }
            Err(argon2::password_hash::Error::Password) => {
                warn!("Password verification failed: Incorrect password.");
                Ok(false) // Password is NOT correct
            }
            Err(e) => {
                error!("Password verification failed with an unexpected error: {:?}", e);
                Err(AppError::InternalServerError("Password verification process failed.".to_string()))
            }
        }
    })
    .await
    .map_err(|e| { // Handles JoinError if the task panics
        error!("Password verification task panicked: {:?}", e);
        AppError::InternalServerError("Password verification process failed unexpectedly.".to_string())
    })?; // This ? unwraps the JoinResult

    // The final ? unwraps the inner Result<bool, AppError>
    verification_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[tokio::test]
    async fn test_hash_and_verify_password_success() {
        let password = SecretString::new("ValidPassword123!".to_string());
        let hashed_password_string = hash_password(password.clone()).await.unwrap();
        let verification_result = verify_password(&hashed_password_string, password).await.unwrap();
        assert!(verification_result);
    }

    #[tokio::test]
    async fn test_verify_password_failure_incorrect_password() {
        let correct_password = SecretString::new("CorrectPassword123!".to_string());
        let incorrect_password = SecretString::new("WrongPassword123!".to_string());
        let hashed_password_string = hash_password(correct_password).await.unwrap();
        let verification_result = verify_password(&hashed_password_string, incorrect_password).await.unwrap();
        assert!(!verification_result);
    }

    #[tokio::test]
    async fn test_verify_password_failure_malformed_hash() {
        let password = SecretString::new("SomePassword123!".to_string());
        let malformed_hash = "this-is-not-a-valid-argon2-hash-string";

        let verification_result = verify_password(malformed_hash, password).await;
        assert!(verification_result.is_err()); // Should return an AppError, not Ok(false)
        if let Err(AppError::InternalServerError(msg)) = verification_result {
            assert!(msg.contains("Stored password hash is invalid."));
        } else {
            panic!("Expected an InternalServerError for a malformed hash.");
        }
    }
}
