use axum::{
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, Json, Response},
};
use serde_json::{json, Value};
use std::process::Command;

/// VULNERABILITY: Command Injection
/// This handler is intentionally vulnerable to command injection attacks.
/// The version parameter is passed directly to a shell command without sanitization.
///
/// Example exploit: /api/';id;'/version-info
/// This will execute: echo ''; id; '' | grep -E "^v[0-9]+"
/// The single quote and semicolon allows command injection: the 'id' command will be executed.
pub async fn version_info(Path(version): Path<String>) -> Json<Value> {
    tracing::warn!("VULNERABILITY: version_info called with potentially malicious input: {}", version);
    // VULNERABLE: Unsanitized user input passed to shell command
    let cmd = format!("echo '{}' | grep -E '^v[0-9]+'", version);
    tracing::debug!("Executing command: {}", cmd);

    let output = Command::new("sh").arg("-c").arg(&cmd).output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();
            tracing::debug!("Command exit code: {:?}", result.status.code());

            Json(json!({
                "version": version,
                "command": cmd,
                "stdout": stdout.trim(),
                "stderr": stderr.trim(),
                "exit_code": result.status.code(),
                "validated": !stdout.trim().is_empty()
            }))
        }
        Err(e) => {
            tracing::error!("Command execution failed: {}", e);
            Json(json!({
                "version": version,
                "command": cmd,
                "error": e.to_string(),
                "validated": false
            }))
        }
    }
}

/// VULNERABILITY: Command Injection via API path
/// Executes system commands based on path parameters
pub async fn api_version_check(Path(version): Path<String>) -> Json<Value> {
    tracing::warn!("VULNERABILITY: api_version_check called with: {}", version);
    // VULNERABLE: Direct command execution with user input
    let cmd = format!("echo 'API Version: {}' && uname -a", version);
    tracing::debug!("Executing command: {}", cmd);

    let output = Command::new("sh").arg("-c").arg(&cmd).output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();

            Json(json!({
                "api_version": version,
                "system_info": stdout,
                "command_executed": cmd
            }))
        }
        Err(e) => Json(json!({
            "api_version": version,
            "error": e.to_string()
        })),
    }
}

/// VULNERABILITY: Git Repository Exposure
/// Exposes .git directory structure and files
/// This simulates accidentally deploying .git folders to production
pub async fn git_directory() -> Json<Value> {
    tracing::warn!("VULNERABILITY: .git directory accessed!");
    Json(json!({
        "error": "403 Forbidden",
        "message": "Directory listing denied",
        "hint": "Try accessing specific files like /.git/config, /.git/HEAD, /.git/logs/HEAD"
    }))
}

pub async fn git_config() -> Json<Value> {
    tracing::warn!("VULNERABILITY: .git/config accessed - repository credentials exposed!");
    Json(json!({
        "file": "/.git/config",
        "content": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = https://github.com/company/super-secret-api.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n[user]\n\tname = John Developer\n\temail = john@company-internal.com\n[credential]\n\thelper = store"
    }))
}

pub async fn git_head() -> Json<Value> {
    tracing::debug!(".git/HEAD accessed");
    Json(json!({
        "file": "/.git/HEAD",
        "content": "ref: refs/heads/main"
    }))
}

pub async fn git_logs_head() -> Json<Value> {
    tracing::warn!("VULNERABILITY: .git/logs/HEAD accessed - commit history exposed!");

    Json(json!({
        "file": "/.git/logs/HEAD",
        "content": "0000000000000000000000000000000000000000 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 John Developer <john@company-internal.com> 1704067200 +0000\tcommit (initial): Initial commit\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 John Developer <john@company-internal.com> 1704153600 +0000\tcommit: Add user authentication\nb2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2 John Developer <john@company-internal.com> 1704240000 +0000\tcommit: Remove hardcoded API keys (oops)\nc3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2 d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3 Sarah Admin <sarah@company-internal.com> 1704326400 +0000\tcommit: Add database credentials to config\nd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3 e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4 John Developer <john@company-internal.com> 1704412800 +0000\tcommit: Production deployment",
        "commits": [
            {
                "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "author": "John Developer <john@company-internal.com>",
                "message": "Initial commit"
            },
            {
                "hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
                "author": "John Developer <john@company-internal.com>",
                "message": "Add user authentication"
            },
            {
                "hash": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "author": "John Developer <john@company-internal.com>",
                "message": "Remove hardcoded API keys (oops)"
            },
            {
                "hash": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
                "author": "Sarah Admin <sarah@company-internal.com>",
                "message": "Add database credentials to config"
            },
            {
                "hash": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
                "author": "John Developer <john@company-internal.com>",
                "message": "Production deployment"
            }
        ]
    }))
}

pub async fn git_index() -> Json<Value> {
    Json(json!({
        "file": "/.git/index",
        "message": "Binary file",
        "entries": [
            {"path": "src/config.rs", "mode": "100644"},
            {"path": "src/main.rs", "mode": "100644"},
            {"path": "src/handlers/auth.rs", "mode": "100644"},
            {"path": "src/models/user.rs", "mode": "100644"},
            {"path": ".env.production", "mode": "100644"},
            {"path": "secrets/database.yml", "mode": "100644"},
            {"path": "Dockerfile", "mode": "100644"},
            {"path": "Cargo.toml", "mode": "100644"}
        ]
    }))
}

/// VULNERABILITY: Swagger UI HTML page
/// Returns HTML for Swagger UI with proper content-type
pub async fn swagger_ui_html() -> Html<String> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DVWAPI - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/swagger/openapi.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
    "#;
    Html(html.to_string())
}

/// ReDoc HTML page
/// Returns HTML for ReDoc documentation viewer
pub async fn redoc_html() -> Html<String> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DVWAPI - ReDoc</title>
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url="/swagger/openapi.json"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>
    "#;
    Html(html.to_string())
}

/// VULNERABILITY: Swagger UI with RCE
/// OpenAPI spec JSON with vulnerable endpoints documented
pub async fn swagger_openapi_spec() -> Json<Value> {
    Json(json!({
        "openapi": "3.0.0",
        "info": {
            "title": "DVWAPI - Damn Vulnerable Web API",
            "version": "1.0.0",
            "description": "Intentionally vulnerable API for security testing and training"
        },
        "servers": [
            {"url": "http://localhost:7341", "description": "Local server"}
        ],
        "paths": {
            "/api/v1/users": {
                "get": {
                    "summary": "List all users",
                    "tags": ["Users"],
                    "responses": {
                        "200": {
                            "description": "Success"
                        }
                    }
                }
            },
            "/swagger/generate": {
                "get": {
                    "summary": "Generate custom API spec (VULNERABLE - RCE)",
                    "tags": ["Vulnerable"],
                    "parameters": [
                        {
                            "name": "title",
                            "in": "query",
                            "description": "API title - VULNERABLE TO COMMAND INJECTION",
                            "required": false,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Generated spec with command execution results"
                        }
                    }
                }
            },
            "/swagger/upload/{spec}": {
                "get": {
                    "summary": "Upload YAML spec (VULNERABLE - RCE)",
                    "tags": ["Vulnerable"],
                    "parameters": [
                        {
                            "name": "spec",
                            "in": "path",
                            "description": "YAML spec content - VULNERABLE TO COMMAND INJECTION",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Spec processed with command execution"
                        }
                    }
                }
            }
        },
        "tags": [
            {"name": "Users", "description": "User management endpoints"},
            {"name": "Vulnerable", "description": "Intentionally vulnerable endpoints"}
        ]
    }))
}

/// VULNERABILITY: RCE through Swagger spec generation
/// This endpoint generates a Swagger spec with a custom title
/// The title parameter is passed to a shell command for "validation"
///
/// Example exploit: /swagger/generate?title=$(whoami)
/// Example exploit: /swagger/generate?title=API;id;
pub async fn swagger_generate(Path(params): Path<String>) -> Json<Value> {
    // Parse query string manually (vulnerable approach)
    let title = if let Some(title_param) = params.split("title=").nth(1) {
        let title_value = title_param.split('&').next().unwrap_or("API");
        urlencoding::decode(title_value)
            .unwrap_or_default()
            .to_string()
    } else {
        "DVWAPI".to_string()
    };

    // VULNERABILITY: Command injection through spec generation
    // Supposedly validates the title by checking if it's alphanumeric
    let validation_cmd = format!("echo '{}' | grep -E '^[a-zA-Z0-9 ]+$'", title);

    let validation_result = Command::new("sh").arg("-c").arg(&validation_cmd).output();

    let is_valid = validation_result
        .as_ref()
        .map(|r| r.status.success())
        .unwrap_or(false);

    let stdout = validation_result
        .as_ref()
        .map(|r| String::from_utf8_lossy(&r.stdout).to_string())
        .unwrap_or_default();

    Json(json!({
        "openapi": "3.0.0",
        "info": {
            "title": title,
            "version": "1.0.0",
            "description": "Auto-generated API specification"
        },
        "metadata": {
            "title_validated": is_valid,
            "validation_output": stdout.trim(),
            "validation_command": validation_cmd
        },
        "servers": [
            {"url": "http://localhost:7341/api/v1"}
        ],
        "paths": {},
        "warning": "This spec generator executes shell commands for validation"
    }))
}

/// VULNERABILITY: YAML spec upload with unsafe deserialization
/// Accepts YAML content and processes it with shell commands
pub async fn swagger_upload_spec(Path(spec_content): Path<String>) -> Json<Value> {
    let decoded_spec = urlencoding::decode(&spec_content)
        .unwrap_or_default()
        .to_string();

    // VULNERABILITY: Processes YAML by piping through shell
    let cmd = format!("echo '{}' | head -10", decoded_spec);

    let output = Command::new("sh").arg("-c").arg(&cmd).output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();

            Json(json!({
                "status": "processed",
                "spec_preview": stdout,
                "message": "YAML spec processed successfully",
                "command_executed": cmd,
                "note": "Spec is validated using shell commands"
            }))
        }
        Err(e) => Json(json!({
            "status": "error",
            "error": e.to_string(),
            "command_executed": cmd
        })),
    }
}

/// VULNERABILITY: Actuator main endpoint
/// Mimics Spring Boot Actuator - exposes management endpoints
pub async fn actuator_index() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /actuator endpoint accessed - exposing management endpoints!");
    Json(json!({
        "_links": {
            "self": {
                "href": "http://localhost:7341/actuator",
                "templated": false
            },
            "health": {
                "href": "http://localhost:7341/actuator/health",
                "templated": false
            },
            "env": {
                "href": "http://localhost:7341/actuator/env",
                "templated": false
            },
            "heapdump": {
                "href": "http://localhost:7341/actuator/heapdump",
                "templated": false
            },
            "shutdown": {
                "href": "http://localhost:7341/actuator/shutdown",
                "templated": false
            }
        }
    }))
}

/// VULNERABILITY: Actuator health endpoint
/// Returns detailed health information including internal system details
pub async fn actuator_health() -> Json<Value> {
    tracing::debug!("Actuator health endpoint accessed");
    Json(json!({
        "status": "UP",
        "components": {
            "diskSpace": {
                "status": "UP",
                "details": {
                    "total": 499963174912_u64,
                    "free": 209715200000_u64,
                    "threshold": 10485760,
                    "path": "/app/.",
                    "exists": true
                }
            },
            "db": {
                "status": "UP",
                "details": {
                    "database": "PostgreSQL",
                    "validationQuery": "isValid()",
                    "result": 0
                }
            },
            "ping": {
                "status": "UP"
            }
        },
        "groups": ["liveness", "readiness"]
    }))
}

/// VULNERABILITY: Actuator env endpoint - exposes ALL environment variables and config
/// This is a critical vulnerability exposing secrets, credentials, and config
pub async fn actuator_env() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /actuator/env accessed - CRITICAL: all configuration and secrets exposed!");
    Json(json!({
        "activeProfiles": ["production"],
        "propertySources": [
            {
                "name": "systemProperties",
                "properties": {
                    "java.runtime.name": {
                        "value": "OpenJDK Runtime Environment"
                    },
                    "java.vm.version": {
                        "value": "17.0.2+8"
                    },
                    "user.dir": {
                        "value": "/app"
                    }
                }
            },
            {
                "name": "systemEnvironment",
                "properties": {
                    "PATH": {
                        "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "origin": "System Environment Property \"PATH\""
                    },
                    "HOME": {
                        "value": "/home/appuser"
                    },
                    "DATABASE_URL": {
                        "value": "postgresql://admin:SecureP@ssw0rd!@prod-db.internal:5432/maindb",
                        "origin": "System Environment Property \"DATABASE_URL\""
                    },
                    "DATABASE_PASSWORD": {
                        "value": "SecureP@ssw0rd!",
                        "origin": "System Environment Property \"DATABASE_PASSWORD\""
                    },
                    "REDIS_URL": {
                        "value": "redis://:redis_secret_pass@redis.internal:6379/0"
                    },
                    "AWS_ACCESS_KEY_ID": {
                        "value": "AKIAIOSFODNN7EXAMPLE"
                    },
                    "AWS_SECRET_ACCESS_KEY": {
                        "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    },
                    "JWT_SECRET": {
                        "value": "super-secret-jwt-key-production-2024"
                    },
                    "STRIPE_SECRET_KEY": {
                        "value": "sk_live_51H8K9jExample"
                    },
                    "ENCRYPTION_KEY": {
                        "value": "aes-256-encryption-key-base64-encoded"
                    },
                    "ADMIN_API_TOKEN": {
                        "value": "Bearer admin_token_12345_secret"
                    },
                    "SMTP_PASSWORD": {
                        "value": "smtp_p@ssw0rd_2024"
                    },
                    "OAUTH_CLIENT_SECRET": {
                        "value": "oauth-secret-key-production"
                    }
                }
            },
            {
                "name": "applicationConfig",
                "properties": {
                    "server.port": {
                        "value": 7341
                    },
                    "spring.datasource.url": {
                        "value": "jdbc:postgresql://prod-db.internal:5432/maindb"
                    },
                    "spring.datasource.username": {
                        "value": "admin"
                    },
                    "spring.datasource.password": {
                        "value": "SecureP@ssw0rd!"
                    },
                    "logging.level.root": {
                        "value": "INFO"
                    }
                }
            }
        ]
    }))
}

/// VULNERABILITY: Actuator heapdump endpoint
/// Simulates a heap dump that could contain sensitive data from memory
pub async fn actuator_heapdump() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /actuator/heapdump accessed - memory dump with sensitive data exposed!");

    // Simulate heap dump metadata
    Json(json!({
        "status": "generated",
        "message": "Heap dump generated",
        "filename": "heapdump-2024-01-15-14-30-00.hprof",
        "size_bytes": 524288000,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "warning": "Heap dumps may contain sensitive data from application memory",
        "memory_snapshot": {
            "total_memory_mb": 512,
            "used_memory_mb": 387,
            "free_memory_mb": 125,
            "heap_objects": 156789,
            "leaked_secrets_preview": {
                "passwords": ["admin123", "SecureP@ssw0rd!", "user_pass_2024"],
                "tokens": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "Bearer admin_token_12345_secret"],
                "api_keys": ["sk_live_51H8K9jExample", "AKIAIOSFODNN7EXAMPLE"],
                "session_ids": ["sess_1a2b3c4d5e6f", "sess_9z8y7x6w5v4u"],
                "credit_cards": ["4532-****-****-1234", "5425-****-****-5678"],
                "internal_ips": ["192.168.1.100", "10.0.0.5", "172.16.0.10"]
            },
            "strings_in_memory": [
                "SELECT * FROM users WHERE password = 'admin123'",
                "Authorization: Bearer secret_token_xyz",
                "API_KEY=sk_live_production_key_12345",
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF..."
            ]
        },
        "download_url": "/actuator/heapdump/download",
        "note": "In production, this would return a binary .hprof file"
    }))
}

/// VULNERABILITY: Actuator shutdown endpoint - unauthenticated shutdown!
/// Allows anyone to shutdown the application without authentication
pub async fn actuator_shutdown() -> Json<Value> {
    tracing::error!("VULNERABILITY: /actuator/shutdown accessed - CRITICAL: unauthenticated shutdown requested!");

    Json(json!({
        "message": "Shutting down application...",
        "status": "SHUTDOWN_INITIATED",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "warning": "This endpoint allows unauthenticated shutdown - CRITICAL VULNERABILITY!",
        "details": {
            "initiated_by": "anonymous",
            "authentication": "none",
            "authorization": "none",
            "graceful_shutdown": true,
            "estimated_downtime_seconds": 5
        },
        "note": "In a real application, this would actually shutdown the server. For demo purposes, shutdown is simulated only."
    }))
}

/// VULNERABILITY: Internal API index (UNDOCUMENTED)
/// Exposes internal endpoints meant for internal services only
pub async fn internal_index() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /internal endpoint accessed - internal API exposed!");
    Json(json!({
        "status": "ok",
        "message": "Internal API - For internal services only",
        "version": "internal-v1",
        "endpoints": [
            "/internal/health",
            "/internal/metrics",
            "/internal/debug",
            "/internal/cache",
            "/internal/db/stats"
        ],
        "warning": "This endpoint should not be publicly accessible",
        "authentication": "none",
        "ip_whitelist": "disabled"
    }))
}

/// VULNERABILITY: Internal health check (UNDOCUMENTED)
/// More detailed than public health, includes sensitive internal services
pub async fn internal_health() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /internal/health accessed - detailed internal health data exposed!");
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": 86400,
        "services": {
            "database": {
                "status": "up",
                "host": "prod-db.internal.corp:5432",
                "database": "maindb",
                "username": "app_user",
                "connection_pool": {
                    "active": 15,
                    "idle": 5,
                    "max": 20,
                    "min": 5
                },
                "slow_queries": 3,
                "last_error": null
            },
            "redis": {
                "status": "up",
                "host": "redis.internal.corp:6379",
                "memory_used_mb": 245,
                "connected_clients": 12,
                "ops_per_sec": 1250,
                "hit_rate": 0.94
            },
            "elasticsearch": {
                "status": "up",
                "cluster": "prod-cluster",
                "nodes": ["es-node-1.internal", "es-node-2.internal", "es-node-3.internal"],
                "indices": 47,
                "documents": 15678901
            },
            "message_queue": {
                "status": "up",
                "broker": "rabbitmq.internal.corp:5672",
                "vhost": "/production",
                "queues": {
                    "email_queue": {
                        "messages": 125,
                        "consumers": 3
                    },
                    "notification_queue": {
                        "messages": 89,
                        "consumers": 2
                    },
                    "analytics_queue": {
                        "messages": 1567,
                        "consumers": 5
                    }
                }
            },
            "internal_services": {
                "auth_service": "http://auth.internal.corp:8080",
                "payment_service": "http://payment.internal.corp:8081",
                "notification_service": "http://notify.internal.corp:8082",
                "analytics_service": "http://analytics.internal.corp:8083"
            }
        },
        "network": {
            "internal_ip": "10.0.1.42",
            "external_ip": "203.0.113.45",
            "hostname": "api-server-prod-01.internal.corp",
            "gateway": "10.0.1.1",
            "dns_servers": ["10.0.0.1", "10.0.0.2"]
        }
    }))
}

/// VULNERABILITY: Internal metrics (UNDOCUMENTED)
/// Exposes detailed operational metrics including usage patterns
pub async fn internal_metrics() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /internal/metrics accessed - sensitive metrics data exposed!");
    Json(json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": 86400,
        "requests": {
            "total": 1567890,
            "per_second": 18.2,
            "per_minute": 1092,
            "per_hour": 65520,
            "by_endpoint": {
                "/api/v1/users": 456789,
                "/api/v1/auth/login": 123456,
                "/api/v2/transactions": 89012,
                "/api/v3/orders": 45678,
                "/graphql": 12345,
                "/internal/health": 8901
            },
            "by_status": {
                "200": 1456789,
                "201": 45678,
                "400": 34567,
                "401": 12345,
                "403": 8901,
                "404": 5678,
                "500": 3456
            },
            "by_method": {
                "GET": 1234567,
                "POST": 234567,
                "PUT": 56789,
                "DELETE": 34567,
                "PATCH": 7401
            }
        },
        "performance": {
            "avg_response_time_ms": 125.4,
            "p50_ms": 89,
            "p95_ms": 456,
            "p99_ms": 1234,
            "slowest_endpoints": [
                {
                    "endpoint": "/api/v2/reports/generate",
                    "avg_ms": 4567,
                    "count": 234
                },
                {
                    "endpoint": "/api/v3/analytics/dashboard",
                    "avg_ms": 2345,
                    "count": 567
                }
            ]
        },
        "database": {
            "queries_total": 5678901,
            "queries_per_second": 65.7,
            "avg_query_time_ms": 23.4,
            "slow_queries": 123,
            "connection_errors": 5,
            "deadlocks": 2,
            "cache_hit_rate": 0.89
        },
        "memory": {
            "heap_used_mb": 387,
            "heap_max_mb": 512,
            "heap_committed_mb": 512,
            "non_heap_used_mb": 89,
            "gc_collections": 234,
            "gc_time_ms": 1234
        },
        "api_keys": {
            "total_active": 1567,
            "usage_by_key": {
                "key_1a2b3c4d": {
                    "requests": 123456,
                    "last_used": "2025-12-07T14:10:00Z",
                    "owner": "customer_123"
                },
                "key_9z8y7x6w": {
                    "requests": 89012,
                    "last_used": "2025-12-07T14:05:00Z",
                    "owner": "partner_corp"
                },
                "key_5v4u3t2s": {
                    "requests": 45678,
                    "last_used": "2025-12-07T14:00:00Z",
                    "owner": "internal_service"
                }
            },
            "rate_limited_keys": 23,
            "revoked_today": 5
        },
        "errors": {
            "total_24h": 12345,
            "by_type": {
                "DatabaseConnectionError": 45,
                "TimeoutException": 123,
                "ValidationError": 8901,
                "AuthenticationError": 2345,
                "InternalServerError": 456
            },
            "recent_errors": [
                {
                    "timestamp": "2025-12-07T14:12:34Z",
                    "type": "DatabaseConnectionError",
                    "message": "Connection to prod-db.internal.corp:5432 refused",
                    "stack_trace": "at db.connect() line 45"
                },
                {
                    "timestamp": "2025-12-07T14:11:12Z",
                    "type": "TimeoutException",
                    "message": "Request to payment_service timed out after 5000ms",
                    "endpoint": "http://payment.internal.corp:8081/charge"
                }
            ]
        },
        "security": {
            "failed_auth_attempts_24h": 3456,
            "blocked_ips": ["198.51.100.23", "203.0.113.67"],
            "suspicious_requests": 234,
            "sql_injection_attempts": 45,
            "xss_attempts": 23,
            "api_abuse_detected": 12
        }
    }))
}

/// VULNERABILITY: Alternative internal endpoint (UNDOCUMENTED)
pub async fn underscore_internal() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /_internal endpoint accessed - alternative internal API exposed!");
    Json(json!({
        "status": "ok",
        "message": "Alternative internal API endpoint",
        "note": "This is an undocumented endpoint for debugging",
        "environment": "production",
        "build": {
            "version": "1.2.3-prod",
            "git_commit": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "build_time": "2025-11-15T10:30:00Z",
            "builder": "jenkins@build-server.internal",
            "rust_version": "1.86.0"
        },
        "config": {
            "debug_mode": false,
            "log_level": "info",
            "max_connections": 1000,
            "timeout_seconds": 30,
            "enable_cors": true,
            "allowed_origins": ["https://app.example.com", "https://admin.example.com"],
            "feature_flags": {
                "new_payment_flow": true,
                "experimental_api": false,
                "admin_dashboard_v2": true
            }
        },
        "endpoints": [
            "/_internal/debug",
            "/_internal/config",
            "/_internal/cache/clear",
            "/_internal/db/migrate"
        ]
    }))
}

/// VULNERABILITY: Private API index (UNDOCUMENTED)
pub async fn private_index() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /private endpoint accessed - private API exposed!");
    Json(json!({
        "status": "ok",
        "message": "Private API - Internal use only",
        "warning": "This API is not meant for external access",
        "authentication": "disabled",
        "endpoints": {
            "metrics": "/private/metrics",
            "admin": "/private/admin",
            "debug": "/private/debug",
            "config": "/private/config",
            "users": "/private/users/all"
        },
        "notes": "All endpoints are unauthenticated for internal convenience"
    }))
}

/// VULNERABILITY: Private metrics endpoint (UNDOCUMENTED)
pub async fn private_metrics() -> Json<Value> {
    tracing::warn!("VULNERABILITY: /private/metrics accessed - private metrics exposed!");
    Json(json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "server": {
            "hostname": "api-prod-01.internal.corp",
            "pid": 12345,
            "port": 7341,
            "workers": 8,
            "threads": 32
        },
        "traffic": {
            "requests_total": 1567890,
            "bandwidth_in_gb": 234.56,
            "bandwidth_out_gb": 567.89,
            "unique_ips_24h": 12345,
            "top_user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) - 45.2%",
                "curl/7.68.0 - 23.1%",
                "python-requests/2.28.1 - 12.7%",
                "PostmanRuntime/7.29.2 - 8.4%",
                "sqlmap/1.6 - 2.1%"
            ]
        },
        "users": {
            "registered_total": 156789,
            "active_24h": 12345,
            "premium_users": 2345,
            "trial_users": 456,
            "admin_users": 23,
            "recently_registered": [
                {
                    "id": 156789,
                    "email": "user@example.com",
                    "registered_at": "2025-12-07T13:45:00Z",
                    "ip": "198.51.100.42"
                },
                {
                    "id": 156788,
                    "email": "another@example.com",
                    "registered_at": "2025-12-07T13:30:00Z",
                    "ip": "203.0.113.89"
                }
            ],
            "highest_api_usage": [
                {
                    "user_id": 1234,
                    "email": "power.user@corp.com",
                    "requests_24h": 50000,
                    "api_key": "key_1a2b3c4d_partial"
                },
                {
                    "user_id": 5678,
                    "email": "bot.account@automated.net",
                    "requests_24h": 35000,
                    "api_key": "key_9z8y7x6w_partial"
                }
            ]
        },
        "revenue": {
            "today": 45678.90,
            "this_week": 234567.80,
            "this_month": 987654.30,
            "currency": "USD",
            "transactions_24h": 2345,
            "average_transaction": 19.47,
            "failed_payments_24h": 123
        },
        "integrations": {
            "stripe": {
                "status": "connected",
                "secret_key": "sk_live_51H8K9j***",
                "webhook_secret": "whsec_***",
                "requests_24h": 2345
            },
            "sendgrid": {
                "status": "connected",
                "api_key": "SG.***",
                "emails_sent_24h": 12345,
                "bounce_rate": 0.023
            },
            "aws": {
                "status": "connected",
                "access_key_id": "AKIA***",
                "s3_requests": 56789,
                "cloudfront_requests": 123456
            }
        },
        "internal_notes": "Remember to rotate API keys next week - current keys expire 2025-12-15"
    }))
}

/// VULNERABILITY: Weak Basic Authentication Middleware
/// Uses hardcoded credentials: admin/admin123
/// This middleware demonstrates common authentication mistakes:
/// - Hardcoded credentials in source code
/// - Weak password
/// - No rate limiting on auth attempts
/// - Credentials visible in logs
pub async fn basic_auth_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // VULNERABILITY: Hardcoded credentials
    const USERNAME: &str = "admin";
    const PASSWORD: &str = "admin123";

    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header {
        if auth_value.starts_with("Basic ") {
            let encoded = &auth_value[6..];

            // Decode base64 using base64 engine
            use base64::{Engine as _, engine::general_purpose};
            if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                    let parts: Vec<&str> = decoded.split(':').collect();
                    if parts.len() == 2 {
                        let (username, password) = (parts[0], parts[1]);

                        // VULNERABILITY: Credentials logged
                        tracing::debug!("Admin auth attempt: username={}, password={}", username, password);

                        // VULNERABILITY: Simple string comparison, no timing-safe comparison
                        if username == USERNAME && password == PASSWORD {
                            tracing::info!("Admin authentication successful for user: {}", username);
                            return Ok(next.run(req).await);
                        } else {
                            tracing::warn!("Admin authentication failed: invalid credentials (username={}, password={})", username, password);
                        }
                    }
                }
            }
        }
    }

    tracing::warn!("Admin authentication failed: missing or invalid Authorization header");

    Err(StatusCode::UNAUTHORIZED)
}

/// VULNERABILITY: Admin index page
/// Lists admin endpoints after authentication
pub async fn admin_index() -> Json<Value> {
    tracing::info!("Admin index accessed");
    Json(json!({
        "status": "authenticated",
        "message": "Admin Panel - Authenticated",
        "user": "admin",
        "role": "super_admin",
        "endpoints": {
            "dashboard": "/admin/dashboard",
            "users": "/admin/users",
            "config": "/admin/config",
            "logs": "/admin/logs",
            "sql": "/admin/sql"
        },
        "note": "All admin endpoints require Basic Auth: admin/admin123"
    }))
}

/// VULNERABILITY: Admin dashboard with sensitive data
/// Exposes critical system information after weak authentication
pub async fn admin_dashboard() -> Json<Value> {
    tracing::warn!("VULNERABILITY: Admin dashboard accessed - exposing sensitive admin data!");
    Json(json!({
        "status": "ok",
        "message": "Admin Dashboard",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "system": {
            "version": "1.2.3-prod",
            "environment": "production",
            "uptime_hours": 720,
            "server_name": "api-prod-01.internal.corp",
            "internal_ip": "10.0.1.42",
            "external_ip": "203.0.113.45"
        },
        "database": {
            "host": "prod-db.internal.corp",
            "port": 5432,
            "database": "maindb",
            "username": "admin",
            "password": "SecureP@ssw0rd!",
            "connection_string": "postgresql://admin:SecureP@ssw0rd!@prod-db.internal.corp:5432/maindb",
            "max_connections": 100,
            "active_connections": 45,
            "total_size_gb": 234.5
        },
        "users": {
            "total": 156789,
            "active_today": 12345,
            "new_today": 234,
            "banned": 567,
            "admin_users": [
                {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@internal.corp",
                    "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYpZRS1KpoS",
                    "api_key": "admin_key_1a2b3c4d5e6f7g8h9i0j",
                    "role": "super_admin",
                    "last_login": "2025-12-07T14:25:00Z",
                    "ip": "10.0.1.100"
                },
                {
                    "id": 2,
                    "username": "support",
                    "email": "support@internal.corp",
                    "password": "support123",
                    "api_key": "support_key_9z8y7x6w5v4u3t2s1r0q",
                    "role": "admin",
                    "last_login": "2025-12-07T13:10:00Z",
                    "ip": "10.0.1.101"
                }
            ]
        },
        "api_keys": {
            "total_active": 1567,
            "admin_keys": [
                "admin_key_1a2b3c4d5e6f7g8h9i0j",
                "master_key_abcdefghijklmnopqrst",
                "root_key_zyxwvutsrqponmlkjihg"
            ],
            "service_keys": {
                "stripe": "sk_live_51H8K9jFZsExample",
                "sendgrid": "SG.1234567890abcdefghij.klmnopqrstuvwxyz",
                "aws_access": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "jwt_secret": "super-secret-jwt-production-key-2024"
            }
        },
        "security": {
            "failed_logins_24h": 3456,
            "blocked_ips": [
                "198.51.100.23",
                "203.0.113.67",
                "192.0.2.89"
            ],
            "recent_attacks": [
                {
                    "type": "SQL Injection",
                    "ip": "198.51.100.23",
                    "endpoint": "/api/v1/users",
                    "timestamp": "2025-12-07T14:15:00Z",
                    "payload": "' OR '1'='1"
                },
                {
                    "type": "XSS Attempt",
                    "ip": "203.0.113.67",
                    "endpoint": "/api/v2/users",
                    "timestamp": "2025-12-07T14:10:00Z",
                    "payload": "<script>alert('xss')</script>"
                }
            ],
            "auth_attempts": {
                "total_24h": 50000,
                "successful": 46544,
                "failed": 3456,
                "brute_force_detected": 23
            }
        },
        "revenue": {
            "today": 45678.90,
            "this_week": 234567.80,
            "this_month": 987654.30,
            "this_year": 8765432.10,
            "currency": "USD",
            "top_customers": [
                {
                    "customer_id": "cust_1234",
                    "name": "Acme Corp",
                    "email": "billing@acme.example",
                    "total_spent": 123456.78,
                    "api_key": "key_acme_1a2b3c4d"
                },
                {
                    "customer_id": "cust_5678",
                    "name": "Tech Industries",
                    "email": "finance@tech.example",
                    "total_spent": 89012.34,
                    "api_key": "key_tech_9z8y7x6w"
                }
            ]
        },
        "infrastructure": {
            "servers": [
                {
                    "name": "api-prod-01",
                    "ip": "10.0.1.42",
                    "ssh_user": "ubuntu",
                    "ssh_key": "/root/.ssh/prod_key.pem",
                    "status": "running"
                },
                {
                    "name": "api-prod-02",
                    "ip": "10.0.1.43",
                    "ssh_user": "ubuntu",
                    "ssh_key": "/root/.ssh/prod_key.pem",
                    "status": "running"
                }
            ],
            "load_balancer": "lb.internal.corp",
            "cdn": "cdn.example.com"
        },
        "backups": {
            "last_backup": "2025-12-07T02:00:00Z",
            "backup_location": "s3://prod-backups-internal/daily/",
            "encryption_key": "backup-encryption-key-aes256-12345",
            "retention_days": 30
        },
        "monitoring": {
            "alerts_24h": 12,
            "critical_alerts": 2,
            "dashboards": {
                "grafana": "https://grafana.internal.corp/admin",
                "kibana": "https://kibana.internal.corp/admin",
                "datadog": "https://app.datadoghq.com"
            },
            "credentials": {
                "grafana_admin": "admin:grafana_password_123",
                "kibana_admin": "elastic:kibana_password_456"
            }
        },
        "notes": [
            "Database credentials need rotation - scheduled for 2025-12-15",
            "Consider implementing 2FA for admin accounts",
            "Review blocked IPs list weekly",
            "Stripe webhook secret expires next month"
        ]
    }))
}
