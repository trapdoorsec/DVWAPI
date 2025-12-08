mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use tower::ServiceExt;

#[tokio::test]
async fn test_admin_without_auth() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_with_weak_password() {
    let app = common::create_test_app();

    // admin:admin123 encoded in base64
    let auth_header = format!("Basic {}", general_purpose::STANDARD.encode("admin:admin123"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header("Authorization", auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["user"], "admin");
}

#[tokio::test]
async fn test_admin_dashboard_with_auth() {
    let app = common::create_test_app();

    let auth_header = format!("Basic {}", general_purpose::STANDARD.encode("admin:admin123"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/dashboard")
                .header("Authorization", auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;

    // Verify all sensitive data is exposed after weak authentication
    assert!(body["database"]["password"].as_str().unwrap().contains("SecureP@ssw0rd!"));
    assert!(body["database"]["connection_string"].is_string());
    assert!(body["api_keys"]["service_keys"]["stripe"].is_string());
    assert!(body["api_keys"]["service_keys"]["aws_secret"].is_string());
    assert!(body["users"]["admin_users"].is_array());
    assert!(body["infrastructure"]["servers"].is_array());
    assert!(body["backups"]["encryption_key"].is_string());
}

#[tokio::test]
async fn test_admin_wrong_password() {
    let app = common::create_test_app();

    let auth_header = format!("Basic {}", general_purpose::STANDARD.encode("admin:wrongpassword"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header("Authorization", auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
