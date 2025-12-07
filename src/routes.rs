use axum::{routing::get, Router};

use crate::handlers;
use crate::models::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::root))
        .route(
            "/users",
            get(handlers::list_users).post(handlers::create_user),
        )
        .route("/users/{id}", get(handlers::get_user))
        .route("/debug/config", get(handlers::debug_secret))
        .route("/admin", get(handlers::debug_secret))
        .route("/.env", get(handlers::debug_secret))
        .with_state(state)
}
