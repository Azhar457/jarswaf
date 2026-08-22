use crate::api::error::ApiError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_EXPIRY_SECS: u64 = 86400; // 24 hours

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub role: String,
}

pub struct AuthService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    admin_password_hash: String,
}

impl AuthService {
    pub fn new(secret: &str, admin_password_hash: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            admin_password_hash: admin_password_hash.to_string(),
        }
    }

    /// Verify password and generate JWT
    pub fn login(&self, password: &str) -> Result<String, ApiError> {
        // Verify password against stored hash
        // For now, simple comparison — production should use argon2
        if password != self.admin_password_hash {
            return Err(ApiError::new("AUTH_REQUIRED", "Invalid password"));
        }

        self.generate_token("admin".to_string())
    }

    /// Generate JWT token
    fn generate_token(&self, subject: String) -> Result<String, ApiError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ApiError::internal(&e.to_string()))?
            .as_secs();

        let claims = Claims {
            sub: subject,
            iat: now,
            exp: now + TOKEN_EXPIRY_SECS,
            role: "admin".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ApiError::internal(&e.to_string()))
    }

    /// Validate JWT token and return claims
    pub fn validate_token(&self, token: &str) -> Result<Claims, ApiError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|_| ApiError::auth_required())?;

        Ok(token_data.claims)
    }

    /// Extract JWT from Authorization header
    pub fn extract_token(header: &str) -> Option<String> {
        header.strip_prefix("Bearer ").map(|t| t.to_string())
    }
}
