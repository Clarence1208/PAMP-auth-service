use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::api_docs::ErrorResponse;
use crate::auth::jwt;

pub async fn auth_middleware(request: Request, next: Next) -> Response {
    // Get authorization header
    let auth_header = match request.headers().get("Authorization") {
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
    match jwt::validate_token(token) {
        Ok(claims) => {
            // Token is valid, continue to handler
            let mut request = request;

            // Store claims in request extensions for access in handlers
            request.extensions_mut().insert(claims);

            next.run(request).await
        }
        Err(e) => {
            // Log the error for debugging
            tracing::error!("JWT validation error: {:?}", e);

            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    message: format!("Token validation error: {:?}", e),
                }),
            )
                .into_response()
        }
    }
}
