use axum::{routing::get, Router};

use crate::handlers::{v1, v2, v3, vulnerable};
use crate::models::AppState;

fn create_v1_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v1::root))
        .route("/users", get(v1::list_users).post(v1::create_user))
        .route("/users/{id}", get(v1::get_user))
        .route("/debug/config", get(v1::debug_secret))
        .route("/admin", get(v1::debug_secret))
        .route("/.env", get(v1::debug_secret))
        .route("/env", get(v1::env_dump))
        .with_state(state)
}

fn create_v2_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v2::root))
        .route("/users", get(v2::list_users).post(v2::create_user))
        .route("/users/{id}", get(v2::get_user))
        .route("/debug/config", get(v2::debug_secret))
        .route("/admin", get(v2::debug_secret))
        .route("/.env", get(v2::debug_secret))
        .route("/env", get(v2::env_dump))
        .with_state(state)
}

fn create_v3_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(v3::root))
        .route("/health", get(v3::health))
        .route("/healthz", get(v3::health))
        .route("/healthcheck", get(v3::health))
        .route("/ready", get(v3::health))
        .route("/readyz", get(v3::health))
        .route("/live", get(v3::health))
        .route("/livez", get(v3::health))
        .route("/status", get(v3::health))
        .route("/ping", get(v3::ping))
        .route("/users", get(v3::list_users).post(v3::create_user))
        .route("/users/{id}", get(v3::get_user))
        .route("/debug/config", get(v3::debug_secret))
        .route("/admin", get(v3::debug_secret))
        .route("/.env", get(v3::debug_secret))
        .route("/env", get(v3::env_dump))
        .with_state(state)
}

pub fn create_router(state: AppState) -> Router {
    let root_router = Router::new()
        .route("/", get(v1::root))
        .with_state(state.clone());

    // VULNERABILITY: Command Injection Routes
    // These routes are intentionally vulnerable to command injection
    // Examples:
    //   /api/v1;id/version-info  - will execute 'id' command
    //   /api/v1$(whoami)/check   - will execute 'whoami' command
    //   /api/v1;cat /etc/passwd/version-info - will read /etc/passwd
    let vulnerable_router = Router::new()
        .route("/api/{version}/version-info", get(vulnerable::version_info))
        .route("/api/{version}/check", get(vulnerable::api_version_check));

    // VULNERABILITY: Git Repository Exposure (UNDOCUMENTED)
    // Simulates accidentally deploying .git folder to production
    // Common attack: attackers scan for /.git/config to find repository URLs,
    // credentials, and commit history
    let git_router = Router::new()
        .route("/.git", get(vulnerable::git_directory))
        .route("/.git/", get(vulnerable::git_directory))
        .route("/.git/config", get(vulnerable::git_config))
        .route("/.git/HEAD", get(vulnerable::git_head))
        .route("/.git/logs/HEAD", get(vulnerable::git_logs_head))
        .route("/.git/index", get(vulnerable::git_index));


    // VULNERABILITY: Swagger UI with RCE
    // Swagger documentation endpoint with command injection vulnerabilities
    // Examples:
    //   /swagger/generate?title=$(whoami) - executes whoami command
    //   /swagger/generate?title=API;id;    - executes id command
    //   /swagger/upload/test;id;           - executes id command
    let swagger_router = Router::new()
        .route("/swagger", get(vulnerable::swagger_ui_html))
        .route("/redoc", get(vulnerable::redoc_html))
        .route("/swagger/openapi.json", get(vulnerable::swagger_openapi_spec))
        .route("/swagger.json", get(vulnerable::swagger_openapi_spec))
        .route("/api-docs", get(vulnerable::swagger_openapi_spec))
        .route("/swagger/generate", get(vulnerable::swagger_generate))
        .route("/swagger/generate/{params}", get(vulnerable::swagger_generate))
        .route("/swagger/upload/{spec}", get(vulnerable::swagger_upload_spec));

    Router::new()
        .merge(root_router)
        .merge(vulnerable_router)
        .merge(git_router)
        .merge(swagger_router)
        .nest("/api/v1", create_v1_routes(state.clone()))
        .nest("/api/v2", create_v2_routes(state.clone()))
        .nest("/api/v3", create_v3_routes(state))
}
