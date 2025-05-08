use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

/// Authentication response after successful login
#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub token: String,
}

/// Error response
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub message: String,
}

/// Authentication callback parameters
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct CallbackParams {
    /// OAuth authorization code
    pub code: String,
    /// OAuth state for CSRF protection
    pub state: String,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::google_handler::google_login,
        crate::handlers::google_handler::google_callback,
        crate::handlers::auth_handler::register_teacher,
    ),
    components(
        schemas(
            AuthResponse,
            ErrorResponse,
            CallbackParams,
            crate::entities::user::RegisterTeacherRequest,
            crate::entities::user::UserRole,
            crate::entities::user::Model
        )
    ),
    tags(
        (name = "authentication", description = "Authentication endpoints")
    ),
    info(
        title = "PAMP Authentication Service API",
        version = "0.1.0",
        description = "API for handling authentication in PAMP services",
    )
)]
pub struct ApiDoc;
