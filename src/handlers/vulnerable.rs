use axum::{extract::Path, response::Json};
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
    // VULNERABLE: Unsanitized user input passed to shell command
    let cmd = format!("echo '{}' | grep -E '^v[0-9]+'", version);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();

            Json(json!({
                "version": version,
                "command": cmd,
                "stdout": stdout.trim(),
                "stderr": stderr.trim(),
                "exit_code": result.status.code(),
                "validated": !stdout.trim().is_empty()
            }))
        }
        Err(e) => Json(json!({
            "version": version,
            "command": cmd,
            "error": e.to_string(),
            "validated": false
        })),
    }
}

/// VULNERABILITY: Command Injection via API path
/// Executes system commands based on path parameters
pub async fn api_version_check(Path(version): Path<String>) -> Json<Value> {
    // VULNERABLE: Direct command execution with user input
    let cmd = format!("echo 'API Version: {}' && uname -a", version);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

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
    Json(json!({
        "error": "403 Forbidden",
        "message": "Directory listing denied",
        "hint": "Try accessing specific files like /.git/config, /.git/HEAD, /.git/logs/HEAD"
    }))
}

pub async fn git_config() -> Json<Value> {
    Json(json!({
        "file": "/.git/config",
        "content": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = https://github.com/company/super-secret-api.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n[user]\n\tname = John Developer\n\temail = john@company-internal.com\n[credential]\n\thelper = store"
    }))
}

pub async fn git_head() -> Json<Value> {
    Json(json!({
        "file": "/.git/HEAD",
        "content": "ref: refs/heads/main"
    }))
}

pub async fn git_logs_head() -> Json<Value> {
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
