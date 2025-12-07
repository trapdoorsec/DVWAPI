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
