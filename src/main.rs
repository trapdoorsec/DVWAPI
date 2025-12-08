mod graphql;
mod handlers;
mod models;
mod routes;

use clap::Parser;
use std::sync::Arc;
use tokio::net;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use models::{AppState, User};

/// DVWAPI - Damn Vulnerable Web API
#[derive(Parser, Debug)]
#[command(name = "DVWAPI")]
#[command(version, about, long_about = None)]
struct Cli {
    /// IP address to bind to
    #[arg(short, long, default_value = "0.0.0.0")]
    ip: String,

    /// Port number to listen on
    #[arg(short, long, default_value_t = 7341)]
    port: u16,

    /// Enable colored console logging
    #[arg(short, long, default_value_t = true)]
    colored: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize colored logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.clone().into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(cli.colored)
                .with_target(false),
        )
        .init();

    let state: AppState = Arc::new(RwLock::new(vec![
        User {
            id: 1,
            name: "admin".into(),
        },
        User {
            id: 2,
            name: "guest".into(),
        },
    ]));

    let app = routes::create_router(state);

    let bind_addr = format!("{}:{}", cli.ip, cli.port);
    tracing::info!("Starting DVWAPI server on {}", bind_addr);
    tracing::warn!("This is an intentionally vulnerable application for security testing!");

    let listener = net::TcpListener::bind(&bind_addr).await.unwrap();
    tracing::info!("Server listening on {}", bind_addr);

    axum::serve(listener, app).await.unwrap()
}
