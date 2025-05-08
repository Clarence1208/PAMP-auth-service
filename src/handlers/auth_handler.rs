use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
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
    api_docs::ErrorResponse, entities::user::RegisterTeacherRequest, services::user_service,
};

#[utoipa::path(
    post,
    path = "/auth/register/teacher",
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
