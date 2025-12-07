use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};

use crate::models::{AppState, CreateUser, User};

pub async fn root() -> Json<Value> {
    Json(json!({
        "status": "success",
        "message": "Vulnerable API v3 - Latest",
        "api_version": "3.0",
        "deprecated": false,
        "endpoints": [
            "/api/v3/users",
            "/api/v3/users/{id}",
            "/api/v3/health"
        ]
    }))
}

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "uptime": "unknown",
        "version": "3.0"
    }))
}

pub async fn list_users(State(users): State<AppState>) -> Json<Value> {
    let users = users.read().await;
    Json(json!({
        "status": "success",
        "data": {
            "users": *users,
            "count": users.len(),
            "page": 1,
            "per_page": users.len()
        },
        "metadata": {
            "api_version": "3.0",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "request_id": uuid::Uuid::new_v4().to_string()
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
                "status": "success",
                "data": {
                    "user": u,
                    "permissions": ["read", "write"]
                },
                "metadata": {
                    "api_version": "3.0",
                    "request_id": uuid::Uuid::new_v4().to_string()
                }
            }))
        })
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "error": {
                    "message": "User not found",
                    "code": "USER_NOT_FOUND",
                    "status": 404
                },
                "metadata": {
                    "api_version": "3.0",
                    "request_id": uuid::Uuid::new_v4().to_string()
                }
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
            "status": "success",
            "data": {
                "user": user,
                "created": true
            },
            "metadata": {
                "api_version": "3.0",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "request_id": uuid::Uuid::new_v4().to_string()
            }
        })),
    )
}

pub async fn debug_secret() -> Json<Value> {
    Json(json!({
        "status": "success",
        "data": {
            "environment": "production",
            "secrets": {
                "db_password": "supersecret123_v3",
                "api_key": "sk_live_99999",
                "db_host": "prod-db.internal",
                "jwt_secret": "not-so-secret-key"
            }
        },
        "metadata": {
            "api_version": "3.0",
            "exposed": true
        }
    }))
}

pub async fn env_dump() -> Json<Value> {
    Json(json!({
        "status": "success",
        "data": {
            "environment_variables": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/home/appuser",
                "USER": "appuser",
                "SHELL": "/bin/bash",
                "DATABASE_URL": "postgresql://admin:password123@db.internal:5432/production",
                "REDIS_URL": "redis://redis.internal:6379",
                "SECRET_KEY": "super-secret-key-do-not-share",
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "STRIPE_SECRET_KEY": "sk_live_51H8Example",
                "JWT_SECRET": "jwt-secret-key-12345",
                "ADMIN_PASSWORD": "admin123",
                "API_TOKEN": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "SMTP_PASSWORD": "email_password_123",
                "SESSION_SECRET": "session-secret-key",
                "NODE_ENV": "production",
                "ENCRYPTION_KEY": "aes-256-key-example",
                "OAUTH_CLIENT_SECRET": "oauth-client-secret-xyz",
                "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
            },
            "total_variables": 18,
            "sensitive_count": 15
        },
        "metadata": {
            "api_version": "3.0",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "request_id": uuid::Uuid::new_v4().to_string(),
            "warning": "CRITICAL: Environment variables exposed",
            "severity": "high"
        }
    }))
}

pub async fn ping() -> Json<Value> {
    Json(json!({
        "pong": "0",
    }))
}