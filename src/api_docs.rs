use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema, Modify};
use utoipa::openapi::security::{SecurityScheme, HttpAuthScheme, HttpBuilder};

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

#[derive(Debug)]
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::google_handler::google_login,
        crate::handlers::google_handler::google_callback,
        crate::handlers::teacher_handler::register_teacher,
        crate::handlers::teacher_handler::login_teacher,
        crate::handlers::user_handler::get_current_user,
        crate::handlers::user_handler::get_user_by_id,
        crate::handlers::user_handler::get_user_by_email,
        crate::handlers::user_handler::get_all_users,
        crate::handlers::debug_handler::debug_token,
        crate::handlers::student_handler::register_students,
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
    modifiers(&SecurityAddon),
    tags(
        (name = "authentication", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints")
    ),
    info(
        title = "PAMP Authentication Service API",
        version = "0.1.0",
        description = "API for handling authentication in PAMP services",
    )
)]
pub struct ApiDoc;
