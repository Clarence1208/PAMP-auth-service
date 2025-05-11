mod common;

use axum::{
    body::to_bytes,
    http::{Method, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

use PAMP_auth_service::{
    api_docs::ErrorResponse,
    entities::user::{UserDTO, UserRole},
};

// Define a constant for the body size limit (16MB)
const BODY_SIZE_LIMIT: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn test_get_current_user_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user
    let user = common::create_test_user(
        db.as_ref(),
        "user@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for user
    let token = common::create_test_token(
        user.user_id,
        &user.email,
        &UserRole::Teacher,
    );

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            "/me",
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let user_dto: UserDTO = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(user_dto.user_id, user.user_id);
    assert_eq!(user_dto.email, user.email);
    assert_eq!(user_dto.first_name, user.first_name);
    assert_eq!(user_dto.last_name, user.last_name);
    assert_eq!(user_dto.role, UserRole::Teacher);
    assert_eq!(user_dto.is_active, user.is_active);
}

#[tokio::test]
async fn test_get_current_user_no_auth_header() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Send request without auth header
    let response = app
        .oneshot(common::create_request(Method::GET, "/me", ""))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "Missing Authorization header");
}

#[tokio::test]
async fn test_get_current_user_invalid_token() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Send request with invalid token
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(axum::http::header::AUTHORIZATION, "Bearer invalid_token")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "Invalid or expired token");
}

#[tokio::test]
async fn test_get_current_user_not_found() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a token with a non-existent user ID
    let non_existent_user_id = uuid::Uuid::new_v4();
    let token = common::create_test_token(
        non_existent_user_id,
        "nonexistent@example.com",
        &UserRole::Teacher,
    );

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            "/me",
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "User not found");
} 