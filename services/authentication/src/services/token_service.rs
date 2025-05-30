use crate::config::JwtConfig;
use crate::errors::AppError;
use crate::models::Claims;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, EncodingKey, Header};
use secrecy::ExposeSecret;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    jwt_config: Arc<JwtConfig>,
    encoding_key: EncodingKey,
}

impl TokenService {
    pub fn new(jwt_config: Arc<JwtConfig>) -> Result<Self, AppError> {
        tracing::info!("Initializing TokenService...");
        let encoding_key = EncodingKey::from_rsa_pem(jwt_config.private_key_pem_pkcs8.expose_secret().as_bytes())
            .map_err(|e| {
                tracing::error!("Failed to create RSA encoding key from PEM: {:?}", e);
                AppError::ConfigError(format!("Invalid JWT private key format: {}", e))
            })?;
        tracing::info!("RSA encoding key created successfully for TokenService.");
        Ok(Self {
            jwt_config,
            encoding_key,
        })
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        username: &str, // Add username to claims
        roles: &[String],  // Pass roles as a slice
    ) -> Result<String, AppError> {
        tracing::debug!(user_id = %user_id, username = %username, "Generating access token");

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
            sub: user_id.to_string(), // Subject is conventionally the user ID
            exp: expiration_time,
            iat: now.timestamp(),
            user_id, // Custom claim with Uuid type
            roles: roles.to_vec(), // Clone roles into the claims
            username: username.to_string(), // Add username to claims
        };

        let header = Header::new(self.jwt_config.algorithm);

        encode(&header, &claims, &self.encoding_key).map_err(|e| {
            tracing::error!("Failed to encode JWT: {:?}", e);
            AppError::TokenCreationError(format!("Could not create access token: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config; // To get a real JwtConfig for testing
    use secrecy::SecretString;
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

    async fn get_test_jwt_config() -> Arc<JwtConfig> {
        dotenvy::dotenv().ok(); // Ensure .env is loaded for test context
        let app_config = load_config().await.expect("Failed to load config for test");
        Arc::new(app_config.jwt_config)
    }

    #[tokio::test]
    async fn test_generate_and_verify_access_token() {
        let jwt_config = get_test_jwt_config().await;
        let token_service = TokenService::new(Arc::clone(&jwt_config)).unwrap();

        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string(), "tester".to_string()];
        let username = "testuser";

        let token = token_service.generate_access_token(user_id, username, &roles).unwrap();
        assert!(!token.is_empty());
        tracing::debug!("Generated test token: {}", token);

        // Verify the token using the public key from the config
        let decoding_key = DecodingKey::from_rsa_pem(jwt_config.public_key_pem_pkcs8.expose_secret().as_bytes())
            .expect("Failed to create RSA decoding key from PEM for test");
        
        let mut validation = Validation::new(jwt_config.algorithm);
        validation.validate_exp = true; // Ensure expiration is checked
        // validation.set_audience(&["your_audience"]); // If you set audience
        // validation.set_issuer(&["your_issuer"]); // If you set issuer

        let token_data = decode::<Claims>(&token, &decoding_key, &validation)
            .expect("Token verification failed in test");

        assert_eq!(token_data.claims.sub, user_id.to_string());
        assert_eq!(token_data.claims.user_id, user_id);
        assert_eq!(token_data.claims.roles, roles);
        assert_eq!(token_data.claims.username, username);
        assert!(token_data.claims.exp > chrono::Utc::now().timestamp());
        assert!(token_data.claims.iat <= chrono::Utc::now().timestamp());
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let mut jwt_config_for_test = (*get_test_jwt_config().await).clone(); // Clone the inner JwtConfig
        jwt_config_for_test.access_token_expires_in_seconds = 1; // Expires in 1 second
        
        let token_service = TokenService::new(Arc::new(jwt_config_for_test.clone())).unwrap();

        let user_id = Uuid::new_v4();
        let roles = vec!["user".to_string()];
        let username = "expiringuser";

        let token = token_service.generate_access_token(user_id, username, &roles).unwrap();
        
        tokio::time::sleep(std::time::Duration::from_secs(2)).await; // Wait for token to expire

        let decoding_key = DecodingKey::from_rsa_pem(jwt_config_for_test.public_key_pem_pkcs8.expose_secret().as_bytes()).unwrap();
        let mut validation = Validation::new(jwt_config_for_test.algorithm);
        // No need to set validate_exp = false, default is true.
        // decode will return an error if exp is invalid.
        let decoded_token_result = decode::<Claims>(&token, &decoding_key, &validation);
        
        assert!(decoded_token_result.is_err());
        if let Err(e) = decoded_token_result {
            assert_eq!(e.kind(), &jsonwebtoken::errors::ErrorKind::ExpiredSignature);
            tracing::debug!("Correctly caught expired token: {:?}", e);
        }
    }
}
