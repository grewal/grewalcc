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

pub async fn verify_password(password_hash_str: &str, password_to_verify: SecretString) -> Result<bool, AppError> {
    debug!("Attempting to verify password.");

    let owned_password_hash_str = password_hash_str.to_string();

    let verification_succeeded = tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&owned_password_hash_str) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to parse stored password hash (potential tampering or corruption) inside spawn_blocking: {:?}", e);
                return Ok(false);
            }
        };

        match Argon2::default()
            .verify_password(password_to_verify.expose_secret().as_bytes(), &parsed_hash)
        {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => {
                error!("Password verification (argon2.verify_password) failed with an unexpected error: {:?}", e);
                Err(e) // Propagate the argon2::password_hash::Error
            }
        }
    })
    .await
    .map_err(|e| { // Handles JoinError
        error!("Password verification task panicked or was cancelled: {:?}", e);
        AppError::InternalServerError("Password verification process failed unexpectedly.".to_string())
    })?; // This ? is for JoinError

    // Now handle the Result from the closure itself
    match verification_succeeded {
        Ok(_) => { // This means argon2.verify_password succeeded
            info!("Password verification successful.");
            Ok(true)
        }
        Err(argon2::password_hash::Error::Password) => {
            warn!("Password verification failed: Incorrect password.");
            Ok(false)
        }
        Err(e) => {
            error!("Password verification process failed with an argon2::password_hash::Error: {:?}", e);
            Err(AppError::InternalServerError(
                "Password verification process encountered an unexpected issue.".to_string(),
            ))
        }
    }
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
    async fn test_verify_password_failure_malformed_hash_handled_in_spawn_blocking() {
        let password = SecretString::new("SomePassword123!".to_string());
        let malformed_hash = "this-is-not-a-valid-argon2-hash-string";
        
        let verification_result = verify_password(malformed_hash, password).await.unwrap();
        assert!(!verification_result, "Verification should fail for a malformed hash that is handled inside spawn_blocking");
    }

    #[tokio::test]
    async fn test_verify_password_with_unparseable_hash_string_outside_spawn() {
        let password = SecretString::new("TestPassword".to_string());
        let unparseable_hash = "$argon2id$v=19$m=19456,t=2,p=1$corruptedsalt$corruptedhash";

        let result = verify_password(unparseable_hash, password).await.unwrap();
        assert!(!result, "Verification should fail for unparseable hash and result in Ok(false)");
    }
}
