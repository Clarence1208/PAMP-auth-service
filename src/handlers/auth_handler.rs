use argon2::{
    password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordVerifier},
    Argon2, PasswordHasher,
};
use axum::{
    extract::{Extension, Json},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    api_docs::{ErrorResponse, AuthResponse}, entities::user::{RegisterTeacherRequest, UserDTO, LoginRequest, UserRole}, services::user_service, auth::jwt,
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
    post,
    path = "/auth/login/teacher",
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

    // Return token
    (
        StatusCode::OK,
        Json(AuthResponse { token }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/auth/debug-token",
    tag = "authentication",
    request_body = String,
    responses(
        (status = 200, description = "Token debug information"),
        (status = 400, description = "Invalid token format", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn debug_token(
    Json(token): Json<String>,
) -> Response {
    use std::env;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde_json::json;

    // Get JWT secret
    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "JWT_SECRET environment variable not set",
                    "hint": "Make sure JWT_SECRET is set in your environment or .env file"
                })),
            )
                .into_response();
        }
    };

    // Try to decode the token without validation first to see what's in it
    let mut no_validation = Validation::default();
    no_validation.validate_exp = false;
    no_validation.validate_nbf = false;
    no_validation.required_spec_claims.clear();
    
    let decoded_without_validation = decode::<serde_json::Value>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &no_validation,
    );

    // Try to decode the token with validation
    let mut validation = Validation::default();
    validation.validate_exp = true;
    
    let decoded_with_validation = decode::<crate::auth::jwt::Claims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    );

    // Return comprehensive debug information
    (
        StatusCode::OK,
        Json(json!({
            "token_header": token.split('.').next().unwrap_or("invalid"),
            "raw_claims": decoded_without_validation.map(|t| t.claims).unwrap_or_else(|_| json!(null)),
            "validation_result": match decoded_with_validation {
                Ok(token_data) => json!({
                    "valid": true,
                    "claims": {
                        "sub": token_data.claims.sub,
                        "email": token_data.claims.email,
                        "role": token_data.claims.role,
                        "iat": token_data.claims.iat,
                        "exp": token_data.claims.exp
                    },
                    "expires_at": chrono::NaiveDateTime::from_timestamp_opt(token_data.claims.exp, 0)
                        .map(|dt| dt.to_string())
                        .unwrap_or_else(|| "invalid timestamp".to_string())
                }),
                Err(e) => json!({
                    "valid": false,
                    "error": format!("{:?}", e),
                    "error_type": format!("{}", e)
                })
            },
            "environment": {
                "jwt_secret_length": jwt_secret.len(),
                "current_time": chrono::Utc::now().timestamp(),
                "current_time_formatted": chrono::Utc::now().to_string()
            }
        })),
    )
        .into_response()
}
