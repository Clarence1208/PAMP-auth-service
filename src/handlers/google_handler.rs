use crate::api_docs::{AuthResponse, ErrorResponse};
use crate::auth::jwt;
use crate::entities::user::UserRole;
use crate::services::user_service;
use crate::OAuthState;
use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use oauth_axum::{CustomProvider, OAuthClient};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

#[utoipa::path(
    get,
    path = "/auth/google",
    tag = "authentication",
    responses(
        (status = 302, description = "Redirect to Google OAuth login page"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn google_login(
    Extension(client): Extension<Arc<CustomProvider>>,
    Extension(state_store): Extension<OAuthState>,
) -> Response {
    // Generate the URL and store the state/verifier
    let result = (*client)
        .clone()
        .generate_url(
            vec!["email".to_string(), "profile".to_string()],
            |state_auth| async move {
                state_store.set(state_auth.state.clone(), state_auth.verifier);
            },
        )
        .await;

    match result {
        Ok(provider) => {
            if let Some(state_auth) = provider.get_state() {
                if let Some(url) = &state_auth.url_generated {
                    return Redirect::to(url).into_response();
                }
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to generate URL".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Error: {:?}", e.type_id()),
            }),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/auth/callback/google",
    tag = "authentication",
    params(
        ("code" = String, Query, description = "OAuth authorization code"),
        ("state" = String, Query, description = "OAuth state for CSRF protection")
    ),
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "User not registered", body = ErrorResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn google_callback(
    Extension(client): Extension<Arc<CustomProvider>>,
    Extension(state_store): Extension<OAuthState>,
    Extension(db): Extension<Arc<DatabaseConnection>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(code) => code.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "Param code manquant".to_string(),
                }),
            )
                .into_response()
        }
    };

    let state = match params.get("state") {
        Some(state) => state.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "Param state manquant".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Retrieve the verifier using the state
    let verifier = match state_store.get(state) {
        Some(verifier) => verifier,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "Invalid state".to_string(),
                }),
            )
                .into_response()
        }
    };

    // Generate the OAuth token from Google
    let oauth_token = match (*client).clone().generate_token(code, verifier).await {
        Ok(token) => token,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: format!("Error exchanging token: {:?}", e.type_id()),
                }),
            )
                .into_response()
        }
    };

    // Fetch user info from Google
    let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
    let client = reqwest::Client::new();
    let user_info_response = match client
        .get(user_info_url)
        .bearer_auth(&oauth_token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Failed to fetch user info: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to fetch user info".to_string(),
                }),
            )
                .into_response();
        }
    };

    let user_info: Value = match user_info_response.json().await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to parse user info: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to parse user info".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Extract user details
    let email = match user_info.get("email").and_then(|e| e.as_str()) {
        Some(email) => email,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "Email not found in Google profile".to_string(),
                }),
            )
                .into_response();
        }
    };

    let google_id = match user_info.get("id").and_then(|id| id.as_str()) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: "ID not found in Google profile".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Get name from profile, use defaults if not found
    let _first_name = user_info
        .get("given_name")
        .and_then(|n| n.as_str())
        .unwrap_or("Google")
        .to_string();

    let _last_name = user_info
        .get("family_name")
        .and_then(|n| n.as_str())
        .unwrap_or("User")
        .to_string();

    // Check if user exists in our database
    let user = match user_service::find_by_email(db.as_ref(), email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Check if user exists by Google ID
            match user_service::find_by_external_auth(db.as_ref(), "google", google_id).await {
                Ok(Some(user)) => user,
                Ok(None) => {
                    // User not registered
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            message: "User not registered. Please register before logging in."
                                .to_string(),
                        }),
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!("Database error checking external auth: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            message: "Database error".to_string(),
                        }),
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            tracing::error!("Database error checking email: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Database error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Get user role
    let role = UserRole::from(user.role.clone());

    // Generate our own JWT token for the user
    let jwt_token = match jwt::create_token(user.user_id, &user.email, &role) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to generate JWT token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Failed to generate JWT token".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Return the JWT token
    (StatusCode::OK, Json(AuthResponse { token: jwt_token })).into_response()
}
