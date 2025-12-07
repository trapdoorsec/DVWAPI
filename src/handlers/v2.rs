use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};

use crate::models::{AppState, CreateUser, User};

pub async fn root() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "message": "Vulnerable API v2",
        "version": "2.0",
        "deprecated": false
    }))
}

pub async fn list_users(State(users): State<AppState>) -> Json<Value> {
    let users = users.read().await;
    Json(json!({
        "data": {
            "users": *users,
            "total": users.len()
        },
        "meta": {
            "version": "2.0",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }
    }))
}

pub async fn get_user(
    Path(id): Path<u32>,
    State(users): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let users = users.read().await;
    users
        .iter()
        .find(|u| u.id == id)
        .map(|u| {
            Json(json!({
                "data": u,
                "meta": {
                    "version": "2.0"
                }
            }))
        })
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "User not found",
                "code": 404
            })),
        ))
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
    (
        StatusCode::CREATED,
        Json(json!({
            "data": user,
            "meta": {
                "version": "2.0",
                "created": true
            }
        })),
    )
}

pub async fn debug_secret() -> Json<Value> {
    Json(json!({
        "config": {
            "db_password": "supersecret123_v2",
            "api_key": "sk_live_67890",
            "db_host": "localhost"
        },
        "version": "2.0"
    }))
}
