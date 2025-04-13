use oauth_axum::providers::google::GoogleProvider;
use oauth_axum::CustomProvider;
use std::env;

pub fn init_google_client() -> CustomProvider {
    let client_id = env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| eprintln!("Missing GOOGLE_CLIENT_ID"))
        .unwrap_or_else(|_| "missing_client_id".to_string());

    let client_secret = env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| eprintln!("Missing GOOGLE_CLIENT_SECRET"))
        .unwrap_or_else(|_| "missing_client_secret".to_string());

    let redirect_uri = env::var("GOOGLE_REDIRECT_URI")
        .map_err(|_| eprintln!("Missing GOOGLE_REDIRECT_URI"))
        .unwrap_or_else(|_| "http://localhost:3000/auth/callback/google".to_string());

    GoogleProvider::new(client_id, client_secret, redirect_uri)
}
