use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use validator::Validate;

use crate::{
    api_docs::{ErrorResponse, RegisterStudentsResponse},
    auth::jwt::Claims,
    entities::user::RegisterStudentsRequest,
    services::user_service,
};

#[utoipa::path(
    post,
    path = "/register/students",
    tag = "authentication",
    security(
        ("bearer_auth" = [])
    ),
    request_body = RegisterStudentsRequest,
    responses(
        (status = 201, description = "Students registered successfully", body = RegisterStudentsResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "User is not a teacher", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn register_students(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    claims: Extension<Claims>,
    Json(payload): Json<RegisterStudentsRequest>,
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

    // Verify that the current user is a teacher
    if claims.role != "TEACHER" {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                message: "Only teachers can register students".to_string(),
            }),
        )
            .into_response();
    }

    // Check if the students list is empty
    if payload.students.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "No students provided".to_string(),
            }),
        )
            .into_response();
    }

    // Register students
    match user_service::create_students(db.as_ref(), payload.students).await {
        Ok(students) => {
            // Convert to DTOs
            let student_dtos: Vec<crate::entities::user::UserDTO> = students
                .into_iter()
                .map(crate::entities::user::UserDTO::from)
                .collect();

            // Return response
            (
                StatusCode::CREATED,
                Json(RegisterStudentsResponse {
                    created_count: student_dtos.len(),
                    students: student_dtos,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create students: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to register students".to_string(),
                }),
            )
                .into_response()
        }
    }
}
