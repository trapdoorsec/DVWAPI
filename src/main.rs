mod handlers;
mod models;
mod routes;

use clap::Parser;
use std::sync::Arc;
use tokio::net;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use models::{AppState, User};

/// DVWAPI - Damn Vulnerable Web API
#[derive(Parser, Debug)]
#[command(name = "DVWAPI")]
#[command(version, about, long_about = None)]
struct Cli {
    /// IP address to bind to
    #[arg(short, long, default_value = "0.0.0.0")]
    ip: String,

    /// Port number to listen on
    #[arg(short, long, default_value_t = 7341)]
    port: u16,

    /// Enable colored console logging
    #[arg(short, long, default_value_t = true)]
    colored: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize colored logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.clone().into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(cli.colored)
                .with_target(false)
        )
        .init();

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

    let app = routes::create_router(state);

    let bind_addr = format!("{}:{}", cli.ip, cli.port);
    tracing::info!("Starting DVWAPI server on {}", bind_addr);
    tracing::warn!("This is an intentionally vulnerable application for security testing!");

    let listener = net::TcpListener::bind(&bind_addr).await.unwrap();
    tracing::info!("Server listening on {}", bind_addr);

    axum::serve(listener, app).await.unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::{Request, StatusCode}, Router};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    fn create_test_app() -> Router {
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

    async fn body_to_json(body: Body) -> Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_root_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["message"], "Vulnerable API v0.1");
    }

    #[tokio::test]
    async fn test_list_users() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert!(body["users"].is_array());
        assert_eq!(body["users"].as_array().unwrap().len(), 2);
        assert_eq!(body["users"][0]["name"], "admin");
        assert_eq!(body["users"][1]["name"], "guest");
    }

    #[tokio::test]
    async fn test_get_user_found() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert_eq!(body["id"], 1);
        assert_eq!(body["name"], "admin");
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users/999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_user() {
        let app = create_test_app();

        let new_user = json!({"name": "testuser"});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/users")
                    .header("content-type", "application/json")
                    .body(Body::from(new_user.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = body_to_json(response.into_body()).await;
        assert_eq!(body["id"], 3);
        assert_eq!(body["name"], "testuser");
    }

    #[tokio::test]
    async fn test_debug_secret_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert_eq!(body["db_password"], "supersecret123");
        assert_eq!(body["api_key"], "sk_live_12345");
    }

    #[tokio::test]
    async fn test_admin_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert!(body.get("db_password").is_some());
        assert!(body.get("api_key").is_some());
    }

    #[tokio::test]
    async fn test_dotenv_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.env")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_to_json(response.into_body()).await;
        assert!(body.get("db_password").is_some());
    }
}
