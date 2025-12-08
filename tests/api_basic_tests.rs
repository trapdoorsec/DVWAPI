mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_root_endpoint() {
    let app = common::create_test_app();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], "1.0");
}

#[tokio::test]
async fn test_v1_list_users() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["users"].is_array());
    assert_eq!(body["users"].as_array().unwrap().len(), 2);
    assert_eq!(body["users"][0]["name"], "admin");
    assert_eq!(body["users"][1]["name"], "guest");
}

#[tokio::test]
async fn test_v2_list_users() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v2/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["data"]["users"].is_array());
    assert_eq!(body["data"]["total"], 2);
    assert_eq!(body["meta"]["version"], "2.0");
}

#[tokio::test]
async fn test_v3_list_users() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v3/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "success");
    assert!(body["data"]["users"].is_array());
    assert_eq!(body["metadata"]["api_version"], "3.0");
}

#[tokio::test]
async fn test_v1_get_user_found() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/users/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["id"], 1);
    assert_eq!(body["name"], "admin");
}

#[tokio::test]
async fn test_v1_get_user_not_found() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/users/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_v1_create_user() {
    let app = common::create_test_app();

    let new_user = json!({"name": "testuser"});

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(new_user.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["id"], 3);
    assert_eq!(body["name"], "testuser");
}

#[tokio::test]
async fn test_v3_health_endpoint() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v3/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["version"], "3.0");
}

#[tokio::test]
async fn test_v1_debug_secret_endpoint() {
    let app = common::create_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/debug/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["db_password"], "supersecret123");
    assert_eq!(body["api_key"], "sk_live_12345");
}
