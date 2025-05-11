use crate::api_docs::ErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[utoipa::path(
    post,
    path = "/debug-token",
    tag = "authentication",
    request_body = String,
    responses(
        (status = 200, description = "Token debug information"),
        (status = 400, description = "Invalid token format", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn debug_token(Json(token): Json<String>) -> Response {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde_json::json;
    use std::env;

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
                    "expires_at": chrono::DateTime::from_timestamp(token_data.claims.exp, 0)
                        .map(|dt| dt.naive_local())
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
