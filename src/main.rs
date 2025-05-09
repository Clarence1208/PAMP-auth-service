use axum::response::Redirect;
use axum::{
    routing::{get, post},
    Extension, Router,
};
use dotenvy::dotenv;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::{Config, SwaggerUi};

mod api_docs;
mod auth;
mod db;
mod entities;
mod handlers;
mod providers;
mod services;

use api_docs::ApiDoc;
use db::{ensure_schema_exists, init_db};
use handlers::auth_handler;
use handlers::google_handler as auth_google;
use providers::google_provider::init_google_client;

use tower_http::cors::{Any, CorsLayer};

// fixme Simple in-memory storage for OAuth state and verifiers
#[derive(Clone)]
pub struct OAuthState {
    states: Arc<Mutex<HashMap<String, String>>>,
}

impl OAuthState {
    fn new() -> Self {
        OAuthState {
            states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set(&self, state: String, verifier: String) {
        let mut states = self
            .states
            .lock()
            .map_err(|_| "Failed to lock mutex")
            .expect("Failed to lock OAuth state mutex");
        states.insert(state, verifier);
    }

    pub fn get(&self, state: String) -> Option<String> {
        let states = self
            .states
            .lock()
            .map_err(|_| "Failed to lock mutex")
            .expect("Failed to lock OAuth state mutex");
        states.get(&state).cloned()
    }
}

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
    tracing::info!("Database schema initialized");

    let google_client = Arc::new(init_google_client());
    let oauth_state = OAuthState::new();

    let api_routes = Router::new().route(
        "/auth/register/teacher",
        post(auth_handler::register_teacher),
    );

    let auth_routes = Router::new()
        .route("/auth/gooogle", get(auth_google::google_login))
        .route("/auth/callback/google", get(auth_google::google_callback));

    let openapi = ApiDoc::openapi();

    let cors_layer = CorsLayer::new().allow_origin(Any); //fixme: when we have the prod url

    let app = Router::new()
        .route("/", get(|| async { "Hello from Auth Service!" }))
        .merge(auth_routes)
        .merge(api_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi, ))
        .layer(cors_layer)
        .layer(Extension(google_client))
        .layer(Extension(oauth_state))
        .layer(Extension(Arc::new(db)));

    start_server(app).await?;

    Ok(())
}

async fn start_server(app: Router) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server started on {}", addr);

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
