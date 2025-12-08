mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_actuator_index() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/actuator")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["_links"]["health"].is_object());
    assert!(body["_links"]["env"].is_object());
    assert!(body["_links"]["heapdump"].is_object());
    assert!(body["_links"]["shutdown"].is_object());
}

#[tokio::test]
async fn test_actuator_health() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/actuator/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "UP");
    assert!(body["components"]["diskSpace"].is_object());
    assert!(body["components"]["db"].is_object());
}

#[tokio::test]
async fn test_actuator_env_secrets_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/actuator/env")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["activeProfiles"][0], "production");

    // Verify sensitive data is exposed
    let props = &body["propertySources"][1]["properties"];
    assert!(props["DATABASE_PASSWORD"]["value"].as_str().unwrap().contains("SecureP@ssw0rd!"));
    assert!(props["AWS_SECRET_ACCESS_KEY"]["value"].is_string());
    assert!(props["JWT_SECRET"]["value"].is_string());
}

#[tokio::test]
async fn test_actuator_heapdump_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/actuator/heapdump")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "generated");

    // Verify leaked secrets in heap
    assert!(body["memory_snapshot"]["leaked_secrets_preview"]["passwords"].is_array());
    assert!(body["memory_snapshot"]["leaked_secrets_preview"]["tokens"].is_array());
    assert!(body["memory_snapshot"]["leaked_secrets_preview"]["api_keys"].is_array());
}

#[tokio::test]
async fn test_actuator_shutdown_no_auth() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/actuator/shutdown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "SHUTDOWN_INITIATED");
    assert_eq!(body["details"]["authentication"], "none");
}
