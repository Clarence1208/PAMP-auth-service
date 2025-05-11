use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub mod api_docs;
pub mod auth;
pub mod db;
pub mod entities;
pub mod handlers;
pub mod providers;
pub mod services;

// Re-export commonly used items for easier use in tests
pub use api_docs::ApiDoc;
pub use auth::middleware::auth_middleware;
pub use db::{ensure_schema_exists, init_db};

// Simple in-memory storage for OAuth state and verifiers
#[derive(Clone)]
pub struct OAuthState {
    states: Arc<Mutex<HashMap<String, String>>>,
}

impl OAuthState {
    pub fn new() -> Self {
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