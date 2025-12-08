mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_internal_index() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["authentication"], "none");
    assert!(body["endpoints"].is_array());
}

#[tokio::test]
async fn test_internal_health_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "healthy");

    // Verify internal infrastructure details exposed
    assert!(body["services"]["database"]["host"].as_str().unwrap().contains("internal.corp"));
    assert!(body["services"]["redis"]["host"].is_string());
    assert!(body["network"]["internal_ip"].is_string());
    assert!(body["network"]["hostname"].is_string());
}

#[tokio::test]
async fn test_internal_metrics_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/internal/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;

    // Verify sensitive metrics exposed
    assert!(body["requests"]["total"].is_number());
    assert!(body["api_keys"]["usage_by_key"].is_object());
    assert!(body["errors"]["recent_errors"].is_array());
    assert!(body["security"]["failed_auth_attempts_24h"].is_number());
}

#[tokio::test]
async fn test_underscore_internal_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/_internal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["environment"], "production");
    assert!(body["build"]["git_commit"].is_string());
    assert!(body["config"]["feature_flags"].is_object());
}

#[tokio::test]
async fn test_private_index() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/private")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["authentication"], "disabled");
    assert!(body["endpoints"].is_object());
}

#[tokio::test]
async fn test_private_metrics_exposure() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/private/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;

    // Verify business-sensitive data exposed
    assert!(body["revenue"]["today"].is_number());
    assert!(body["users"]["registered_total"].is_number());
    assert!(body["integrations"]["stripe"]["secret_key"].is_string());
    assert!(body["integrations"]["aws"]["access_key_id"].is_string());
}
