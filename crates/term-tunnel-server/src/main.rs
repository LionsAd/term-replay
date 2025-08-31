use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use std::io::{self, Write};
use tokio::signal;
use tracing;

use term_protocol::{handshake::TUNNEL_READY_SEQUENCE, SessionInfo};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    run_tunnel_server().await
}

/// Main tunnel server implementation
pub async fn run_tunnel_server() -> Result<()> {
    tracing::info!("🚇 Starting term-tunnel-server");

    // Phase 1: Emit handshake sequence to establish tunnel
    emit_handshake()?;

    // Phase 2: Start HTTP/WebSocket server (placeholder)
    start_http_server().await?;

    tracing::info!("🚇 term-tunnel-server exiting");
    Ok(())
}

/// Emit the handshake sequence to stdout to signal tunnel readiness
fn emit_handshake() -> Result<()> {
    tracing::info!("🤝 Emitting tunnel handshake sequence");

    // Print the handshake sequence to stdout
    // This will be detected by the term-tunnel client
    io::stdout().write_all(TUNNEL_READY_SEQUENCE)?;
    io::stdout().flush()?;

    tracing::info!("✅ Handshake emitted successfully");
    Ok(())
}

/// Start the HTTP/WebSocket server (placeholder implementation)
async fn start_http_server() -> Result<()> {
    tracing::info!("🌐 Starting HTTP/WebSocket server on localhost:8080");

    // Create the HTTP router with placeholder endpoints
    let app = create_app_router().await;

    // Start the server in a background task
    let server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("Failed to bind to localhost:8080");

        tracing::info!("🔌 HTTP server listening on http://127.0.0.1:8080");

        axum::serve(listener, app).await.expect("Server failed");
    });

    // Wait for shutdown signal
    tracing::info!("⏳ Server running - waiting for shutdown signal (Ctrl+C)");
    wait_for_shutdown().await;

    // Gracefully shutdown
    tracing::info!("🛑 Shutdown signal received, stopping server");
    server_handle.abort();

    Ok(())
}

/// Create the Axum app router with HTTP endpoints
async fn create_app_router() -> Router {
    // Placeholder session state
    let session_state = create_placeholder_sessions();

    Router::new()
        .route("/list-sessions", get(list_sessions))
        .route("/health", get(health_check))
        .with_state(session_state)
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "term-tunnel-server",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// List sessions endpoint (placeholder implementation)
async fn list_sessions(
    State(sessions): State<Vec<SessionInfo>>,
) -> Result<Json<Vec<SessionInfo>>, StatusCode> {
    tracing::debug!("📋 Listing {} placeholder sessions", sessions.len());
    Ok(Json(sessions))
}

/// Create some placeholder session data for testing
fn create_placeholder_sessions() -> Vec<SessionInfo> {
    vec![
        SessionInfo {
            id: "term-replay".to_string(),
            name: "Default Session".to_string(),
            pid: std::process::id(),
            created: "2025-01-01T00:00:00Z".to_string(),
        },
        SessionInfo {
            id: "test-session".to_string(),
            name: "Test Session".to_string(),
            pid: std::process::id() + 1,
            created: "2025-01-01T00:01:00Z".to_string(),
        },
    ]
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check_endpoint() {
        let app = create_app_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "term-tunnel-server");
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_list_sessions_endpoint() {
        let app = create_app_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/list-sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let sessions: Vec<SessionInfo> = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "term-replay");
        assert_eq!(sessions[0].name, "Default Session");
        assert_eq!(sessions[1].id, "test-session");
        assert_eq!(sessions[1].name, "Test Session");
    }

    #[tokio::test]
    async fn test_placeholder_session_creation() {
        let sessions = create_placeholder_sessions();

        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "term-replay");
        assert_eq!(sessions[1].id, "test-session");

        // Verify sessions have different PIDs
        assert_ne!(sessions[0].pid, sessions[1].pid);
    }

    #[tokio::test]
    async fn test_handshake_emission() {
        // Test that handshake function doesn't panic
        let result = emit_handshake();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unknown_endpoint() {
        let app = create_app_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
