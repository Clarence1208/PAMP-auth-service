use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{self, Request},
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use sea_orm::{Database, DatabaseConnection, DbErr};
use std::{env, sync::Arc};
use uuid::Uuid;

use PAMP_auth_service::{
    api_docs::{AuthResponse, ErrorResponse},
    auth::jwt::{self, Claims},
    db,
    entities::user::{Model as UserModel, UserDTO, UserRole},
    handlers,
};

// Define a constant for the body size limit (16MB)
const BODY_SIZE_LIMIT: usize = 16 * 1024 * 1024;

/// Sets up the JWT_SECRET environment variable for tests
pub fn setup_jwt_secret() {
    env::set_var("JWT_SECRET", "test_secret_for_tests");
}

/// Creates an in-memory SQLite database for testing
pub async fn setup_test_db() -> Result<DatabaseConnection, DbErr> {
    dotenv().ok();
    setup_jwt_secret();
    let db = Database::connect("sqlite::memory:").await?;
    PAMP_auth_service::db::ensure_schema_exists(&db).await?;
    Ok(db)
}

/// Creates a test app with routes for testing
pub fn create_test_app(db: Arc<DatabaseConnection>) -> Router {
    Router::new()
        .route(
            "/register/teacher",
            post(handlers::teacher_handler::register_teacher),
        )
        .route(
            "/login/teacher",
            post(handlers::teacher_handler::login_teacher),
        )
        .route(
            "/register/students",
            post(handlers::student_handler::register_students),
        )
        .route("/me", get(handlers::user_handler::get_current_user))
        .route("/users", get(handlers::user_handler::get_all_users))
        .route(
            "/users/email/{email}",
            get(handlers::user_handler::get_user_by_email),
        )
        .route("/users/{id}", get(handlers::user_handler::get_user_by_id))
        .route("/debug-token", post(handlers::debug_handler::debug_token))
        .layer(Extension(db))
}

/// Creates a test user in the database
pub async fn create_test_user(
    db: &DatabaseConnection,
    email: &str,
    password_hash: Option<String>,
    role: UserRole,
) -> Result<UserModel, DbErr> {
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, Set};

    let now = Utc::now();
    let user = PAMP_auth_service::entities::user::ActiveModel {
        user_id: Set(Uuid::new_v4()),
        email: Set(email.to_string()),
        password_hash: Set(password_hash),
        first_name: Set("Test".to_string()),
        last_name: Set("User".to_string()),
        role: Set(role.to_string()),
        external_auth_provider: Set(None),
        external_auth_id: Set(None),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user.insert(db).await
}

/// Creates a JWT token for testing
pub fn create_test_token(user_id: Uuid, email: &str, role: &UserRole) -> String {
    setup_jwt_secret();
    PAMP_auth_service::auth::jwt::create_token(user_id, email, role)
        .expect("Failed to create test token")
}

/// Creates a test request with authorization header
pub fn create_authorized_request<B>(
    method: http::Method,
    uri: &str,
    token: &str,
    body: B,
) -> Request<Body>
where
    B: Into<Body>,
{
    Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
        .body(body.into())
        .unwrap()
}

/// Creates a test request without authorization
pub fn create_request<B>(method: http::Method, uri: &str, body: B) -> Request<Body>
where
    B: Into<Body>,
{
    Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(body.into())
        .unwrap()
}

/// Helper to parse response body as JSON
pub async fn parse_json<T: serde::de::DeserializeOwned>(body: Body) -> T {
    let bytes = to_bytes(body, BODY_SIZE_LIMIT).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
