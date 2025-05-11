mod common;

use axum::{
    body::to_bytes,
    extract::Request,
    http::{Method, StatusCode},
    middleware::{from_fn, Next},
    response::Response,
};
use std::sync::Arc;
use tower::ServiceExt;

use PAMP_auth_service::{
    api_docs::{ErrorResponse, RegisterStudentsResponse},
    auth::jwt::Claims,
    entities::user::{RegisterStudentRequest, RegisterStudentsRequest, UserRole},
};

// Define a constant for the body size limit (16MB)
const BODY_SIZE_LIMIT: usize = 16 * 1024 * 1024;

// Mock auth middleware that injects claims
async fn mock_auth_middleware(
    claims: Claims,
    mut req: Request,
    next: Next,
) -> Response {
    req.extensions_mut().insert(claims);
    next.run(req).await
}

#[tokio::test]
async fn test_register_students_success() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a teacher user
    let teacher = common::create_test_user(
        db.as_ref(),
        "teacher@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for teacher
    let token = common::create_test_token(
        teacher.user_id,
        &teacher.email,
        &UserRole::Teacher,
    );

    // Create claims for middleware
    let claims = Claims {
        sub: teacher.user_id.to_string(),
        email: teacher.email.clone(),
        role: UserRole::Teacher.to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };

    // Add middleware layer for auth
    let app = app.layer(from_fn(move |req, next| {
        let claims_clone = claims.clone();
        async move {
            mock_auth_middleware(claims_clone, req, next).await
        }
    }));

    // Create request payload
    let students = vec![
        RegisterStudentRequest {
            email: "student1@example.com".to_string(),
            first_name: "Student".to_string(),
            last_name: "One".to_string(),
        },
        RegisterStudentRequest {
            email: "student2@example.com".to_string(),
            first_name: "Student".to_string(),
            last_name: "Two".to_string(),
        },
    ];

    let payload = RegisterStudentsRequest { students };

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::POST,
            "/register/students",
            &token,
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::CREATED);

    // Check response body
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let response: RegisterStudentsResponse = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(response.created_count, 2);
    assert_eq!(response.students.len(), 2);
    assert_eq!(response.students[0].email, "student1@example.com");
    assert_eq!(response.students[1].email, "student2@example.com");
}

#[tokio::test]
async fn test_register_students_empty_list() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a teacher user
    let teacher = common::create_test_user(
        db.as_ref(),
        "teacher@example.com",
        Some("hash".to_string()),
        UserRole::Teacher,
    )
    .await
    .unwrap();

    // Create token for teacher
    let token = common::create_test_token(
        teacher.user_id,
        &teacher.email,
        &UserRole::Teacher,
    );

    // Create claims for middleware
    let claims = Claims {
        sub: teacher.user_id.to_string(),
        email: teacher.email.clone(),
        role: UserRole::Teacher.to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };

    // Add middleware layer for auth
    let app = app.layer(from_fn(move |req, next| {
        let claims_clone = claims.clone();
        async move {
            mock_auth_middleware(claims_clone, req, next).await
        }
    }));

    // Create request payload with empty students list
    let payload = RegisterStudentsRequest { students: vec![] };

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::POST,
            "/register/students",
            &token,
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert!(error.message.contains("Validation error") || error.message.contains("No students provided"));
}

#[tokio::test]
async fn test_register_students_not_a_teacher() {
    // Setup
    let db = Arc::new(common::setup_test_db().await.unwrap());
    let app = common::create_test_app(db.clone());

    // Create a student user
    let student = common::create_test_user(
        db.as_ref(),
        "student@example.com",
        Some("hash".to_string()),
        UserRole::Student,
    )
    .await
    .unwrap();

    // Create token for student
    let token = common::create_test_token(
        student.user_id,
        &student.email,
        &UserRole::Student,
    );

    // Create claims for middleware with student role
    let claims = Claims {
        sub: student.user_id.to_string(),
        email: student.email.clone(),
        role: UserRole::Student.to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };
    
    // Add middleware layer for auth with student role
    let app = app.layer(from_fn(move |req, next| {
        let claims_clone = claims.clone();
        async move {
            mock_auth_middleware(claims_clone, req, next).await
        }
    }));

    // Create request payload
    let students = vec![
        RegisterStudentRequest {
            email: "student1@example.com".to_string(),
            first_name: "Student".to_string(),
            last_name: "One".to_string(),
        },
    ];

    let payload = RegisterStudentsRequest { students };

    // Send request
    let response = app
        .oneshot(common::create_authorized_request(
            Method::POST,
            "/register/students",
            &token,
            serde_json::to_string(&payload).unwrap(),
        ))
        .await
        .unwrap();

    // Assert response
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Check error message
    let body = to_bytes(response.into_body(), BODY_SIZE_LIMIT).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(error.message, "Only teachers can register students");
} 