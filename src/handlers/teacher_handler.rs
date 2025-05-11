use argon2::{
    password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordVerifier},
    Argon2, PasswordHasher,
};
use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use validator::Validate;

use crate::{
    api_docs::{ErrorResponse, AuthResponse}, 
    entities::user::{RegisterTeacherRequest, LoginRequest, UserRole}, 
    services::user_service, 
    auth::jwt,
};

#[utoipa::path(
    post,
    path = "/register/teacher",
    tag = "authentication",
    request_body = RegisterTeacherRequest,
    responses(
        (status = 201, description = "Teacher registered successfully"),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 409, description = "Email already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn register_teacher(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    Json(payload): Json<RegisterTeacherRequest>,
) -> Response {
    // Validate input
    if let Err(errors) = payload.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: format!("Validation error: {}", errors),
            }),
        )
            .into_response();
    }

    // Check if email already exists
    match user_service::find_by_email(db.as_ref(), &payload.email).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    message: "Email already exists".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response();
        }
        _ => {}
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            tracing::error!("Password hashing error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to hash password".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Create new teacher user
    match user_service::create_teacher(db.as_ref(), payload, Some(password_hash)).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => {
            tracing::error!("Failed to create user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to create user".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/login/teacher",
    tag = "authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 403, description = "User is not a teacher", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn login_teacher(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // Validate input
    if let Err(errors) = payload.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: format!("Validation error: {}", errors),
            }),
        )
            .into_response();
    }

    // Find user by email
    let user = match user_service::find_by_email(db.as_ref(), &payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Invalid email or password".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Check if user is a teacher
    let role = UserRole::from(user.role.clone());
    if role != UserRole::Teacher {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                message: "User is not a teacher".to_string(),
            }),
        )
            .into_response();
    }

    // Verify password
    let password_hash = match &user.password_hash {
        Some(hash) => hash,
        None => {
            // User doesn't have a password (probably OAuth user)
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Password login not available for this account".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse the stored password hash
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => {
            tracing::error!("Failed to parse password hash");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Authentication error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify the password
    let argon2 = Argon2::default();
    if argon2.verify_password(payload.password.as_bytes(), &parsed_hash).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "Invalid email or password".to_string(),
            }),
        )
            .into_response();
    }

    // Generate JWT token
    let token = match jwt::create_token(user.user_id, &user.email, &role) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to generate JWT token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to generate authentication token".to_string(),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(AuthResponse { token }),
    )
        .into_response()
} 