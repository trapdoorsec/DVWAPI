mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_graphql_users_query() {
    let app = common::create_test_app();

    let query = json!({
        "query": "{ users { id name } }"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(query.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["data"]["users"].is_array());
    assert_eq!(body["data"]["users"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_graphql_secrets_exposure() {
    let app = common::create_test_app();

    let query = json!({
        "query": "{ secrets { key value } }"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(query.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["data"]["secrets"].is_array());
    let secrets = body["data"]["secrets"].as_array().unwrap();
    assert!(secrets.iter().any(|s| s["key"] == "API_KEY"));
    assert!(secrets.iter().any(|s| s["key"] == "DB_PASSWORD"));
}

#[tokio::test]
async fn test_graphql_system_info_exposure() {
    let app = common::create_test_app();

    let query = json!({
        "query": "{ systemInfo { hostname platform } }"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(query.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert!(body["data"]["systemInfo"]["hostname"].is_string());
    assert!(body["data"]["systemInfo"]["platform"].is_string());
}

#[tokio::test]
async fn test_graphql_create_user_mutation() {
    let app = common::create_test_app();

    let mutation = json!({
        "query": "mutation { createUser(name: \"hacker\") { id name } }"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(mutation.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    assert_eq!(body["data"]["createUser"]["name"], "hacker");
    assert_eq!(body["data"]["createUser"]["id"], 3);
}

#[tokio::test]
async fn test_graphql_delete_user_no_auth() {
    let app = common::create_test_app();

    let mutation = json!({
        "query": "mutation { deleteUser(id: 1) }"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(mutation.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = common::body_to_json(response.into_body()).await;
    // Mutation should succeed without authentication
    assert_eq!(body["data"]["deleteUser"], true);
}
