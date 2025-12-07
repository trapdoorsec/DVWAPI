use axum::{
    extract::Path,
    response::{Html, Json},
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
