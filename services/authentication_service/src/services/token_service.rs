use crate::config::JwtConfig;
use crate::errors::AppError;
use crate::models::Claims;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, EncodingKey, Header, decode, DecodingKey, Validation};
use secrecy::ExposeSecret;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    jwt_config: Arc<JwtConfig>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl TokenService {
    pub fn new(jwt_config: Arc<JwtConfig>) -> Result<Self, AppError> {
        tracing::info!("Initializing TokenService...");

        let private_pem = jwt_config.private_key_pem_pkcs8.expose_secret();
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| {
                tracing::error!("Failed to create RSA encoding key from private PEM: {:?}", e);
                AppError::ConfigError(format!("Invalid JWT private key: {}", e))
            })?;
        tracing::debug!("RSA encoding key created successfully.");

        let public_pem = jwt_config.public_key_pem_pkcs8.expose_secret();
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| {
                tracing::error!("Failed to create RSA decoding key from public PEM: {:?}", e);
                AppError::ConfigError(format!("Invalid JWT public key: {}", e))
            })?;
        tracing::debug!("RSA decoding key created successfully.");
        
        tracing::info!("TokenService initialized successfully with signing and verification keys.");
        Ok(Self {
            jwt_config,
            encoding_key,
            decoding_key,
        })
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        username: &str,
        email: &str,
        roles: &[String],
    ) -> Result<String, AppError> {
        tracing::debug!(user_id = %user_id, username = %username, email = %email, "Generating access token");

        let now = Utc::now();
        let expires_in_seconds = self.jwt_config.access_token_expires_in_seconds;
        
        let expiration_time = match now.checked_add_signed(Duration::seconds(expires_in_seconds)) {
            Some(exp_time) => exp_time.timestamp(),
            None => {
                tracing::error!("Failed to calculate token expiration time due to overflow.");
                return Err(AppError::TokenCreationError(
                    "Failed to calculate token expiration.".to_string(),
                ));
            }
        };

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration_time,
            iat: now.timestamp(),
            user_id,
            roles: roles.to_vec(),
            username: username.to_string(),
            email: email.to_string(),
        };

        let header = Header::new(self.jwt_config.algorithm);

        encode(&header, &claims, &self.encoding_key).map_err(|e| {
            tracing::error!("Failed to encode JWT: {:?}", e);
            AppError::TokenCreationError(format!("Could not create access token: {}", e))
        })
    }

    pub fn verify_access_token(&self, token_str: &str) -> Result<Claims, AppError> {
        tracing::debug!("Attempting to verify access token");

        let mut validation = Validation::new(self.jwt_config.algorithm);
        validation.validate_exp = true; 

        match decode::<Claims>(token_str, &self.decoding_key, &validation) {
            Ok(token_data) => {
                tracing::info!(user_id = %token_data.claims.user_id, "Access token verified successfully");
                Ok(token_data.claims)
            }
            Err(e) => {
                tracing::warn!("Access token verification failed: {:?}", e);
                let error_message = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::InvalidToken => "Token is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => "Token signature is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => "Token algorithm is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token has expired.".to_string(),
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => "Token issuer is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => "Token audience is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::InvalidSubject => "Token subject is invalid.".to_string(),
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature => "Token is not yet valid (nbf).".to_string(),
                    jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) => format!("Token is missing required claim: {}", claim),
                    _ => "Token validation failed.".to_string(),
                };
                Err(AppError::Unauthorized(error_message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config;
    // SecretString is imported via super, Algorithm also via super jsonwebtoken import

    async fn get_test_jwt_config() -> Arc<JwtConfig> {
        dotenvy::dotenv().ok();
        let app_config = load_config().await.expect("Failed to load config for test. Ensure .env has JWT keys.");
        Arc::new(app_config.jwt_config)
    }

    #[tokio::test]
    async fn test_generate_and_verify_access_token() {
        let jwt_config = get_test_jwt_config().await;
        let token_service = TokenService::new(Arc::clone(&jwt_config)).unwrap();

        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string(), "tester".to_string()];
        let username = "testuser";
        let email = "testuser@example.com";

        // MODIFIED: Pass email to generate_access_token
        let token = token_service.generate_access_token(user_id, username, email, &roles).unwrap();
        assert!(!token.is_empty());
        tracing::debug!("Generated test token for verification: {}", token);

        let claims_result = token_service.verify_access_token(&token);
        assert!(claims_result.is_ok(), "Token should be valid. Error: {:?}", claims_result.err());

        let claims = claims_result.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.user_id, user_id);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.username, username);
        assert_eq!(claims.email, email);
        assert!(claims.exp > chrono::Utc::now().timestamp());
        assert!(claims.iat <= chrono::Utc::now().timestamp());
    }

    #[tokio::test]
    async fn test_token_expiration_verified_by_service() {
        let mut jwt_config_for_test = (*get_test_jwt_config().await).clone();
        jwt_config_for_test.access_token_expires_in_seconds = 1; 
        
        let token_service = TokenService::new(Arc::new(jwt_config_for_test.clone())).unwrap();

        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string()];
        let username = "expiringuser";
        let email = "expiringuser@example.com";

        let token = token_service.generate_access_token(user_id, username, email, &roles).unwrap();
        
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let claims_result = token_service.verify_access_token(&token);
        assert!(claims_result.is_err());

        if let Err(AppError::Unauthorized(msg)) = claims_result {
            assert!(msg.contains("Token has expired."), "Error message mismatch: {}", msg);
            tracing::debug!("Correctly caught expired token via service: {}", msg);
        } else {
            panic!("Expected AppError::Unauthorized for expired token, got {:?}", claims_result);
        }
    }

    #[tokio::test]
    async fn test_verify_invalid_signature_token() {
        let jwt_config = get_test_jwt_config().await;
        let token_service = TokenService::new(Arc::clone(&jwt_config)).unwrap();
        
        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string()];
        let username = "testuser";
        let email = "invalid@example.com";

        let token = token_service.generate_access_token(user_id, username, email, &roles).unwrap();
        
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        let tampered_signature = format!("{}X", parts[2].chars().take(parts[2].len() -1 ).collect::<String>());
        let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_signature);

        let claims_result = token_service.verify_access_token(&tampered_token);
        assert!(claims_result.is_err());

        if let Err(AppError::Unauthorized(msg)) = claims_result {
            assert!(msg.to_lowercase().contains("signature"), "Error message mismatch for invalid signature: {}", msg);
            tracing::debug!("Correctly caught invalid signature token via service: {}", msg);
        } else {
            panic!("Expected AppError::Unauthorized for invalid signature, got {:?}", claims_result);
        }
    }
}
