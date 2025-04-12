use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::env;
use crate::entities::user::UserRole;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub subject: String,
    pub email: String,
    pub role: String,
    pub issued_at: i64,
    pub expiration_time: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("JWT configuration error: {0}")]
    Config(String),
}

pub fn create_token(user_id: Uuid, email: &str, role: &UserRole) -> Result<String, JwtError> {
    let jwt_secret = env::var("JWT_SECRET")
        .map_err(|_| JwtError::Config("JWT_SECRET not set".to_string()))?;
    
    let role_str = match role {
        UserRole::Teacher => "TEACHER",
        UserRole::Student => "STUDENT",
    };
    
    let now = Utc::now();
    let expires_at = now + Duration::hours(24);
    
    let claims = Claims {
        subject: user_id.to_string(),
        email: email.to_string(),
        role: role_str.to_string(),
        issued_at: now.timestamp(),
        expiration_time: expires_at.timestamp(),
    };
    
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(JwtError::Jwt)
}

pub fn validate_token(token: &str) -> Result<Claims, JwtError> {
    let jwt_secret = env::var("JWT_SECRET")
        .map_err(|_| JwtError::Config("JWT_SECRET not set".to_string()))?;
    
    let validation = Validation::default();
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(JwtError::Jwt)?;
    
    Ok(token_data.claims)
} 