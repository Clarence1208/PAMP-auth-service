use std::any::Any;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    extract::{Extension, Query},
};
use oauth_axum::{OAuthClient, CustomProvider};
use std::collections::HashMap;
use std::sync::Arc;
use crate::OAuthState;

pub async fn google_login(
    Extension(client): Extension<Arc<CustomProvider>>,
    Extension(state_store): Extension<OAuthState>,
) -> Response {
    // Generate the URL and store the state/verifier
    let result = (*client).clone()
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
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate URL".to_string()).into_response()
        },
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {:?}", e.type_id())).into_response()
        }
    }
}

pub async fn google_callback(
    Extension(client): Extension<Arc<CustomProvider>>,
    Extension(state_store): Extension<OAuthState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(code) => code.clone(),
        None => return (StatusCode::BAD_REQUEST, "Param code manquant".to_string()).into_response(),
    };
    
    let state = match params.get("state") {
        Some(state) => state.clone(),
        None => return (StatusCode::BAD_REQUEST, "Param state manquant".to_string()).into_response(),
    };
    
    // Retrieve the verifier using the state
    let verifier = match state_store.get(state) {
        Some(verifier) => verifier,
        None => return (StatusCode::BAD_REQUEST, "Invalid state".to_string()).into_response(),
    };
    
    // Generate the token
    match (*client).clone().generate_token(code, verifier).await {
        Ok(token) => {
            (StatusCode::OK, format!("Login Google OK ! Token: {}", token)).into_response()
        },
        Err(e) => {
            (StatusCode::BAD_REQUEST, format!("Erreur échange de token: {:?}", e.type_id())).into_response()
        }
    }
}
