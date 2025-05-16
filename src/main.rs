use axum::{
    http,
    routing::{get, post},
    Extension, Router,
};
use std::env;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use dotenvy::dotenv;
use log::info;
use reqwest::{header, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api_docs;
mod auth;
mod db;
mod entities;
mod handlers;
mod providers;
mod services;

use api_docs::ApiDoc;
use auth::middleware::auth_middleware;
use db::{ensure_schema_exists, init_db};
use handlers::debug_handler;
use handlers::google_handler;
use handlers::student_handler;
use handlers::teacher_handler;
use handlers::user_handler;
use providers::google_provider::init_google_client;
use PAMP_auth_service::OAuthState;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv().ok();

    let db = init_db().await?;

    ensure_schema_exists(&db).await?;
    info!("Database schema initialized");

    let google_client = Arc::new(init_google_client());
    let oauth_state = OAuthState::new();

    let cors_layer = CorsLayer::new()
        .allow_origin(
            env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:5173".to_string())
                .parse::<http::HeaderValue>()
                .unwrap_or_else(|_| {
                    log::warn!("Failed to parse origin, falling back to Any");
                    http::HeaderValue::from_static("*")
                }),
        )
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(86400));

    let app = Router::new()
        .route("/", get(|| async { "Hello from Auth Service!" }))
        .merge(createGoogleRoutes())
        .merge(createAPIRoutes())
        .merge(createSwagger())
        .layer(cors_layer)
        .layer(Extension(google_client))
        .layer(Extension(oauth_state))
        .layer(Extension(Arc::new(db)));

    start_server(app).await?;

    Ok(())
}

fn createSwagger() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi())
}

fn createAPIRoutes() -> Router {
    Router::new()
        .route("/register/teacher", post(teacher_handler::register_teacher))
        .route("/login/teacher", post(teacher_handler::login_teacher))
        .route("/debug-token", post(debug_handler::debug_token))
        .route(
            "/register/students",
            post(student_handler::register_students)
                .route_layer(axum::middleware::from_fn(auth_middleware)),
        )
        .route(
            "/me",
            get(user_handler::get_current_user)
                .route_layer(axum::middleware::from_fn(auth_middleware)),
        )
        .route(
            "/users",
            get(user_handler::get_all_users)
                .route_layer(axum::middleware::from_fn(auth_middleware)),
        )
        .route(
            "/users/{id}",
            get(user_handler::get_user_by_id)
                .route_layer(axum::middleware::from_fn(auth_middleware)),
        )
        .route(
            "/users/email/{email}",
            get(user_handler::get_user_by_email)
                .route_layer(axum::middleware::from_fn(auth_middleware)),
        )
}

fn createGoogleRoutes() -> Router {
    Router::new()
        .route("/login/google", get(google_handler::google_login))
        .route(
            "/login/callback/google",
            get(google_handler::google_callback),
        )
}

async fn start_server(app: Router) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Server started on {}", addr);

    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            axum::serve(listener, app.into_make_service()).await?;
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to bind to address: {}", e);
            Err(e.into())
        }
    }
}
