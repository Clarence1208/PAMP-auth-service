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
async fn test_get_user_by_id_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user
    let user = common::create_test_user(
        db.as_ref(),
        "user.byid@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for authentication
    let token = common::create_test_token(user.user_id, &user.email, &UserRole::Teacher);

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            &format!("/users/{}", user.user_id),
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let user_dto: UserDTO = serde_json::from_slice(&body).unwrap();

    assert_eq!(user_dto.user_id, user.user_id);
    assert_eq!(user_dto.email, user.email);
    assert_eq!(user_dto.first_name, user.first_name);
    assert_eq!(user_dto.last_name, user.last_name);
    assert_eq!(user_dto.role, UserRole::Teacher);
}

#[tokio::test]
async fn test_get_user_by_id_not_found() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user for authentication
    let user = common::create_test_user(
        db.as_ref(),
        "auth.user@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for authentication
    let token = common::create_test_token(user.user_id, &user.email, &UserRole::Teacher);

    // Non-existent user ID
    let non_existent_id = uuid::Uuid::new_v4();

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            &format!("/users/{}", non_existent_id),
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "User not found");
}

#[tokio::test]
async fn test_get_user_by_email_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user
    let user = common::create_test_user(
        db.as_ref(),
        "user.byemail@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for authentication
    let token = common::create_test_token(user.user_id, &user.email, &UserRole::Teacher);

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            &format!("/users/email/{}", user.email),
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let user_dto: UserDTO = serde_json::from_slice(&body).unwrap();

    assert_eq!(user_dto.user_id, user.user_id);
    assert_eq!(user_dto.email, user.email);
    assert_eq!(user_dto.first_name, user.first_name);
    assert_eq!(user_dto.last_name, user.last_name);
    assert_eq!(user_dto.role, UserRole::Teacher);
}

#[tokio::test]
async fn test_get_user_by_email_not_found() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user for authentication
    let user = common::create_test_user(
        db.as_ref(),
        "auth.user2@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for authentication
    let token = common::create_test_token(user.user_id, &user.email, &UserRole::Teacher);

    // Non-existent email
    let non_existent_email = "nonexistent@example.com";

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            &format!("/users/email/{}", non_existent_email),
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "User not found");
}

#[tokio::test]
async fn test_get_all_users() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create multiple test users
    let user1 = common::create_test_user(
        db.as_ref(),
        "user1@example.com",
        Some("hash1".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    let user2 = common::create_test_user(
        db.as_ref(),
        "user2@example.com",
        Some("hash2".to_string()),
        UserRole::Student,
    )
    .await
    .unwrap();

    // Create token for authentication
    let token = common::create_test_token(user1.user_id, &user1.email, &UserRole::Teacher);

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::GET,
            "/users",
            &token,
            "",
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let users: Vec<UserDTO> = serde_json::from_slice(&body).unwrap();

    // We should have at least our two created users
    assert!(users.len() >= 2);

    // Check that our created users are in the list
    let contains_user1 = users.iter().any(|u| u.user_id == user1.user_id);
    let contains_user2 = users.iter().any(|u| u.user_id == user2.user_id);

    assert!(contains_user1, "Result should contain user1");
    assert!(contains_user2, "Result should contain user2");
}
