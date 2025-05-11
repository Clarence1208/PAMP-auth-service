use axum::{
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    api_docs::ErrorResponse,
    auth::jwt,
    entities::user::UserDTO,
    services::user_service,
};

#[utoipa::path(
    get,
    path = "/me",
    tag = "authentication",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Current user information", body = UserDTO),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn get_current_user(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    headers: HeaderMap,
) -> Response {
    // Extract token from Authorization header
    let auth_header = match headers.get("Authorization") {
        Some(header) => header,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Missing Authorization header".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse token from header
    let auth_header_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Invalid Authorization header".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Extract token from "Bearer {token}"
    let token = match auth_header_str.strip_prefix("Bearer ") {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Invalid token format".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Validate token
    let claims = match jwt::validate_token(token) {
        Ok(claims) => claims,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: "Invalid or expired token".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse user ID from claims
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Invalid user ID in token".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Find user in database
    match user_service::find_by_id(db.as_ref(), user_id).await {
        Ok(Some(user)) => {
            // Convert to DTO
            let user_dto = UserDTO::from(user);
            Json(user_dto).into_response()
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID (UUID)")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User information", body = UserDTO),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn get_user_by_id(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    Path(id): Path<String>,
) -> Response {
    // Parse user ID from path parameter
    let user_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "Invalid user ID format".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Find user in database
    match user_service::find_by_id(db.as_ref(), user_id).await {
        Ok(Some(user)) => {
            // Convert to DTO
            let user_dto = UserDTO::from(user);
            Json(user_dto).into_response()
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/users/email/{email}",
    tag = "users",
    params(
        ("email" = String, Path, description = "User email")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User information", body = UserDTO),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn get_user_by_email(
    Extension(db): Extension<Arc<DatabaseConnection>>,
    Path(email): Path<String>,
) -> Response {
    // Find user in database by email
    match user_service::find_by_email(db.as_ref(), &email).await {
        Ok(Some(user)) => {
            // Convert to DTO
            let user_dto = UserDTO::from(user);
            Json(user_dto).into_response()
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of all users", body = Vec<UserDTO>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn get_all_users(
    Extension(db): Extension<Arc<DatabaseConnection>>,
) -> Response {
    // Find all users in database
    match user_service::find_all(db.as_ref()).await {
        Ok(users) => {
            // Convert all users to DTOs
            let user_dtos: Vec<UserDTO> = users.into_iter().map(UserDTO::from).collect();
            Json(user_dtos).into_response()
        },
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response()
        }
    }
} 