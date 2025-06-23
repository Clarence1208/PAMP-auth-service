mod common;

use argon2::PasswordHasher;
use axum::{
    body::to_bytes,
    http::{Method, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

use PAMP_auth_service::{
    api_docs::{AuthResponse, ErrorResponse},
    entities::user::{LoginRequest, RegisterTeacherRequest, UserRole},
};

// Define a constant for the body size limit (16MB)
const BODY_SIZE_LIMIT: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn test_register_teacher_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create request payload
    let payload = RegisterTeacherRequest {
        email: "test.teacher@example.com".to_string(),
        password: "password123".to_string(),
        first_name: "Test".to_string(),
        last_name: "Teacher".to_string(),
    };

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/register/teacher",
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_register_teacher_duplicate_email() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a user first
    let email = "duplicate@example.com";
    common::create_test_user(
        db.as_ref(),
        email,
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create request payload with same email
    let payload = RegisterTeacherRequest {
        email: email.to_string(),
        password: "password123".to_string(),
        first_name: "Test".to_string(),
        last_name: "Teacher".to_string(),
    };

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/register/teacher",
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "Email already exists");
}

#[tokio::test]
async fn test_register_teacher_invalid_input() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create invalid request payload (short password)
    let payload = RegisterTeacherRequest {
        email: "test.teacher@example.com".to_string(),
        password: "short".to_string(), // Less than 8 characters
        first_name: "Test".to_string(),
        last_name: "Teacher".to_string(),
    };

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/register/teacher",
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Check error message contains validation error
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert!(error.message.contains("Validation error"));
    assert!(error
        .message
        .contains("Password must be at least 8 characters"));
}

#[tokio::test]
async fn test_login_teacher_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user with argon2 hashed password
    let email = "login.test@example.com";
    let password = "password123";

    // Hash password
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = argon2::Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Create user
    let user = common::create_test_user(db.as_ref(), email, Some(password_hash), UserRole::Teacher)
        .await
        .unwrap();

    // Create login payload
    let payload = LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
    };

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/login/teacher",
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::OK);

    // Check token is returned
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let auth_response: AuthResponse = serde_json::from_slice(&body).unwrap();
    assert!(!auth_response.token.is_empty());
}

#[tokio::test]
async fn test_login_teacher_invalid_credentials() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a test user
    let email = "login.test2@example.com";
    let password = "password123";

    // Hash password
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = argon2::Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Create user
    common::create_test_user(db.as_ref(), email, Some(password_hash), UserRole::Teacher)
        .await
        .unwrap();

    // Create login payload with wrong password
    let payload = LoginRequest {
        email: email.to_string(),
        password: "wrong_password".to_string(),
    };

    // Send request
    let response = app
        .oneshot(common::create_request(
            Method::POST,
            "/login/teacher",
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "Invalid email or password");
}

//fixme uncomment when login as student is removed (prod situation)
// #[tokio::test]
// async fn test_login_teacher_not_a_teacher() {
//     // Setup
//     let db = Arc::new(common::setup_test_db().await.unwrap());
//     let app = common::create_test_app(db.clone());
//
//     // Create a test user with student role
//     let email = "student@example.com";
//     let password = "password123";
//
//     // Hash password
//     let salt =
//         argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
//     let argon2 = argon2::Argon2::default();
//     let password_hash = argon2
//         .hash_password(password.as_bytes(), &salt)
//         .unwrap()
//         .to_string();
//
//     // Create user with student role
//     common::create_test_user(db.as_ref(), email, Some(password_hash), UserRole::Student)
//         .await
//         .unwrap();
//
//     // Create login payload
//     let payload = LoginRequest {
//         email: email.to_string(),
//         password: password.to_string(),
//     };
//
//     // Send request
//     let response = app
//         .oneshot(common::create_request(
//             Method::POST,
//             "/login/teacher",
//             serde_json::to_string(&payload).unwrap(),
//         ))
//         .await
//         .unwrap();
//
//     // Assert response
//     assert_eq!(response.status(), StatusCode::FORBIDDEN);
//
//     // Check error message
//     let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT)
//         .await
//         .unwrap();
//     let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
//     assert_eq!(error.message, "User is not a teacher");
// }
