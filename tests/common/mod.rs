use axum::{body::Body, Router};
use DVWAPI::{models::{AppState, User}, routes};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn create_test_app() -> Router {
    let state: AppState = Arc::new(RwLock::new(vec![
        User {
            id: 1,
            name: "admin".into(),
        },
        User {
            id: 2,
            name: "guest".into(),
        },
    ]));

    routes::create_router(state)
}

pub async fn body_to_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}
