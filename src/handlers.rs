use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};

use crate::models::{AppState, CreateUser, User};

pub async fn root() -> Json<Value> {
    Json(json!({ "status": "ok", "message": "Vulnerable API v0.1" }))
}

pub async fn list_users(State(users): State<AppState>) -> Json<Value> {
    let users = users.read().await;
    Json(json!({ "users": *users }))
}

pub async fn get_user(
    Path(id): Path<u32>,
    State(users): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    let users = users.read().await;
    users
        .iter()
        .find(|u| u.id == id)
        .map(|u| Json(json!(u)))
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_user(
    State(users): State<AppState>,
    Json(input): Json<CreateUser>,
) -> (StatusCode, Json<Value>) {
    let mut users = users.write().await;
    let id = users.len() as u32 + 1;
    let user = User {
        id,
        name: input.name,
    };
    users.push(user.clone());
    (StatusCode::CREATED, Json(json!(user)))
}

pub async fn debug_secret() -> Json<Value> {
    Json(json!({
        "db_password": "supersecret123",
        "api_key": "sk_live_12345"
    }))
}
