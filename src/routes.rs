use axum::{routing::get, Router};

use crate::handlers::{v1, v2, v3};
use crate::models::AppState;

fn create_v1_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v1::root))
        .route("/users", get(v1::list_users).post(v1::create_user))
        .route("/users/{id}", get(v1::get_user))
        .route("/debug/config", get(v1::debug_secret))
        .route("/admin", get(v1::debug_secret))
        .route("/.env", get(v1::debug_secret))
        .with_state(state)
}

fn create_v2_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v2::root))
        .route("/users", get(v2::list_users).post(v2::create_user))
        .route("/users/{id}", get(v2::get_user))
        .route("/debug/config", get(v2::debug_secret))
        .route("/admin", get(v2::debug_secret))
        .route("/.env", get(v2::debug_secret))
        .with_state(state)
}

fn create_v3_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v3::root))
        .route("/health", get(v3::health))
        .route("/users", get(v3::list_users).post(v3::create_user))
        .route("/users/{id}", get(v3::get_user))
        .route("/debug/config", get(v3::debug_secret))
        .route("/admin", get(v3::debug_secret))
        .route("/.env", get(v3::debug_secret))
        .with_state(state)
}

pub fn create_router(state: AppState) -> Router {
    let root_router = Router::new()
        .route("/", get(v1::root))
        .with_state(state.clone());

    Router::new()
        .merge(root_router)
        .nest("/api/v1", create_v1_routes(state.clone()))
        .nest("/api/v2", create_v2_routes(state.clone()))
        .nest("/api/v3", create_v3_routes(state))
}
