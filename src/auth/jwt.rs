use crate::entities::user::UserRole;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    // Standard JWT claims
    pub sub: String, // subject (user ID)
    pub exp: i64,    // expiration time
    pub iat: i64,    // issued at

    // Custom claims
    pub email: String,
    pub role: String,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("JWT configuration error: {0}")]
    Config(String),
}

pub fn create_token(user_id: Uuid, email: &str, role: &UserRole) -> Result<String, JwtError> {
    let jwt_secret =
        env::var("JWT_SECRET").map_err(|_| JwtError::Config("JWT_SECRET not set".to_string()))?;

    let role_str = match role {
        UserRole::Teacher => "TEACHER",
        UserRole::Student => "STUDENT",
    };

    let now = Utc::now();
    let expires_at = now + Duration::hours(24);

    let claims = Claims {
        // Standard claims
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),

        // Custom claims
        email: email.to_string(),
        role: role_str.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(JwtError::Jwt)
}

pub fn validate_token(token: &str) -> Result<Claims, JwtError> {
    let jwt_secret =
        env::var("JWT_SECRET").map_err(|_| JwtError::Config("JWT_SECRET not set".to_string()))?;

    let mut validation = Validation::default();
    validation.validate_exp = true; // Ensure expiration validation is enabled

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(JwtError::Jwt)?;

    Ok(token_data.claims)
}
