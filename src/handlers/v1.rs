use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};

use crate::models::{AppState, CreateUser, User};

pub async fn root() -> Json<Value> {
    tracing::debug!("v1 root endpoint accessed");
    Json(json!({
        "status": "ok",
        "message": "Vulnerable API v1",
        "version": "1.0"
    }))
}

pub async fn list_users(State(users): State<AppState>) -> Json<Value> {
    let users = users.read().await;
    tracing::debug!("v1 listing {} users", users.len());
    Json(json!({ "users": *users }))
}

pub async fn get_user(
    Path(id): Path<u32>,
    State(users): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!("v1 fetching user with id: {}", id);
    let users = users.read().await;
    users
        .iter()
        .find(|u| u.id == id)
        .map(|u| {
            tracing::debug!("v1 user found: {}", u.name);
            Json(json!(u))
        })
        .ok_or_else(|| {
            tracing::debug!("v1 user {} not found", id);
            StatusCode::NOT_FOUND
        })
}

pub async fn create_user(
    State(users): State<AppState>,
    Json(input): Json<CreateUser>,
) -> (StatusCode, Json<Value>) {
    tracing::debug!("v1 creating user with name: {}", input.name);
    let mut users = users.write().await;
    let id = users.len() as u32 + 1;
    let user = User {
        id,
        name: input.name,
    };
    users.push(user.clone());
    tracing::info!("v1 user created: id={}, name={}", user.id, user.name);
    (StatusCode::CREATED, Json(json!(user)))
}

pub async fn debug_secret() -> Json<Value> {
    tracing::warn!("v1 debug_secret endpoint accessed - secrets exposed!");
    Json(json!({
        "db_password": "supersecret123",
        "api_key": "sk_live_12345"
    }))
}

pub async fn env_dump() -> Json<Value> {
    tracing::warn!("v1 env_dump endpoint accessed - environment variables exposed!");
    Json(json!({
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/home/appuser",
        "USER": "appuser",
        "SHELL": "/bin/bash",
        "DATABASE_URL": "postgresql://admin:password123@db.internal:5432/production",
        "REDIS_URL": "redis://redis.internal:6379",
        "SECRET_KEY": "super-secret-key-do-not-share",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }))
}
