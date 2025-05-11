mod common;

use axum::{
    body::to_bytes,
    http::{Method, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use PAMP_auth_service::entities::user::UserRole;

// Define a constant for the body size limit (16MB)
const BODY_SIZE_LIMIT: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn test_debug_token_valid_token() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a valid token
    let user_id = Uuid::new_v4();
    let email = "test@example.com";
    let role = UserRole::Teacher;
    let token = common::create_test_token(user_id, email, &role);

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/debug-token",
            serde_json::to_string(&token).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let debug_info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    // Check that the token is valid
    let validation_result = &debug_info["validation_result"];
    assert_eq!(validation_result["valid"], true);
    
    // Check that the claims are correct
    let claims = &validation_result["claims"];
    assert_eq!(claims["sub"], user_id.to_string());
    assert_eq!(claims["email"], email);
    assert_eq!(claims["role"], role.to_string());
}

#[tokio::test]
async fn test_debug_token_invalid_token() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create an invalid token
    let token = "invalid.token.format";

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/debug-token",
            serde_json::to_string(&token).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let debug_info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    // Check that the token is invalid
    let validation_result = &debug_info["validation_result"];
    assert_eq!(validation_result["valid"], false);
    
    // Check that there's an error message
    assert!(validation_result["error"].is_string());
    assert!(validation_result["error_type"].is_string());
}

#[tokio::test]
async fn test_debug_token_expired_token() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create an expired token manually
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::env;
    
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "test_secret".to_string());
    
    let claims = PAMP_auth_service::auth::jwt::Claims {
        sub: Uuid::new_v4().to_string(),
        email: "expired@example.com".to_string(),
        role: UserRole::Teacher.to_string(),
        iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
        exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(), // Expired 1 hour ago
    };
    
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap();

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/debug-token",
            serde_json::to_string(&token).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let debug_info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    // Check that the token is invalid due to expiration
    let validation_result = &debug_info["validation_result"];
    assert_eq!(validation_result["valid"], false);
    
    // Check that the error is about expiration
    let error = validation_result["error"].as_str().unwrap();
    assert!(error.contains("ExpiredSignature") || error.contains("expired"));
} 