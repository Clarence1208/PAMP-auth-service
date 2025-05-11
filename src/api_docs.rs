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

/// Student registration response
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegisterStudentsResponse {
    pub created_count: usize,
    pub students: Vec<crate::entities::user::UserDTO>,
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
        crate::handlers::auth_handler::get_current_user,
        crate::handlers::auth_handler::login_teacher,
        crate::handlers::auth_handler::debug_token,
        crate::handlers::auth_handler::register_students,
    ),
    components(
        schemas(
            AuthResponse,
            ErrorResponse,
            CallbackParams,
            RegisterStudentsResponse,
            crate::entities::user::RegisterTeacherRequest,
            crate::entities::user::LoginRequest,
            crate::entities::user::RegisterStudentRequest,
            crate::entities::user::RegisterStudentsRequest,
            crate::entities::user::UserRole,
            crate::entities::user::Model,
            crate::entities::user::UserDTO
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
