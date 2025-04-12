use axum::{routing::get, Extension, Router};
use dotenvy::dotenv;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod handlers;
mod providers;
mod api_docs;

use handlers::google_handler as auth;
use providers::google_provider::init_google_client;
use api_docs::ApiDoc;

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
        let mut states = self.states.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        states.insert(state, verifier);
    }

    pub fn get(&self, state: String) -> Option<String> {
        let states = self.states
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        states.get(&state).cloned()
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    dotenv().ok();

    let google_client = Arc::new(init_google_client());
    let oauth_state = OAuthState::new();

    let openapi = ApiDoc::openapi();

    let app = Router::new()
        .route("/", get(|| async { "Hello from Auth Service!" }))
        .route("/auth/google", get(auth::google_login))
        .route("/auth/callback/google", get(auth::google_callback))
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", openapi)
        )
        .layer(Extension(google_client))
        .layer(Extension(oauth_state));

    start_server(app).await;
}

async fn start_server(app: Router) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Serveur lancé sur {}", addr);

    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                eprintln!("Server error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Failed to bind to address: {}", e);
        }
    }
}
