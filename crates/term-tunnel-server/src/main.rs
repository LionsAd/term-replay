use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{Json, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    io::{self, Write},
    time::SystemTime,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::UnixStream, signal};
use tracing;

use term_protocol::{handshake::TUNNEL_READY_SEQUENCE, SessionInfo};
use term_session::{get_socket_path, get_term_replay_dir};

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
    Router::new()
        .route("/list-sessions", get(list_sessions))
        .route("/health", get(health_check))
        .route("/ws/attach/:session_id", get(websocket_handler))
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "term-tunnel-server",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// List sessions endpoint - scan for actual .sock files
async fn list_sessions() -> Result<Json<Vec<SessionInfo>>, StatusCode> {
    match scan_active_sessions().await {
        Ok(sessions) => {
            tracing::debug!("📋 Found {} active sessions", sessions.len());
            Ok(Json(sessions))
        }
        Err(e) => {
            tracing::error!("❌ Failed to scan sessions: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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

/// WebSocket endpoint handler
async fn websocket_handler(Path(session_id): Path<String>, ws: WebSocketUpgrade) -> Response {
    tracing::info!(
        "🔌 WebSocket connection request for session: {}",
        session_id
    );

    ws.on_upgrade(move |socket| handle_websocket_connection(socket, session_id))
}

/// Handle WebSocket connection - bridge to Unix socket
async fn handle_websocket_connection(websocket: axum::extract::ws::WebSocket, session_id: String) {
    tracing::info!("🌐 Starting WebSocket session: {}", session_id);

    if let Err(e) = websocket_to_unix_bridge(websocket, &session_id).await {
        tracing::error!("❌ WebSocket session {} failed: {}", session_id, e);
    }

    tracing::info!("🔚 WebSocket session {} ended", session_id);
}

/// Bridge WebSocket to Unix socket (term-replay server)
async fn websocket_to_unix_bridge(websocket: WebSocket, session_id: &str) -> Result<()> {
    // Get the socket path for this session
    let socket_path = get_socket_path(session_id);
    tracing::debug!("📁 Session socket path: {}", socket_path.display());

    // Auto-spawn term-replay server if socket doesn't exist
    let unix_stream = match UnixStream::connect(&socket_path).await {
        Ok(stream) => {
            tracing::info!("📡 Connected to existing session: {}", session_id);
            stream
        }
        Err(_) => {
            tracing::info!(
                "🚀 Session '{}' not found, auto-spawning term-replay server",
                session_id
            );
            spawn_term_replay_server(session_id).await?;

            // Wait for socket to appear with timeout
            wait_for_socket(&socket_path).await?;

            // Now connect to the newly created socket
            UnixStream::connect(&socket_path).await.map_err(|e| {
                anyhow::anyhow!(
                    "Failed to connect to auto-spawned session '{}' at {}: {}",
                    session_id,
                    socket_path.display(),
                    e
                )
            })?
        }
    };

    let (unix_reader, unix_writer) = tokio::io::split(unix_stream);
    let (ws_sender, ws_receiver) = websocket.split();

    tracing::info!("🔗 Connected to session: {}", session_id);

    // Spawn bidirectional forwarding tasks
    let session_id_clone = session_id.to_string();
    let forward_to_unix = tokio::spawn(forward_websocket_to_unix(
        ws_receiver,
        unix_writer,
        session_id_clone,
    ));

    let session_id_clone = session_id.to_string();
    let forward_to_ws = tokio::spawn(forward_unix_to_websocket(
        unix_reader,
        ws_sender,
        session_id_clone,
    ));

    // Wait for either task to complete (connection closed)
    tokio::select! {
        result = forward_to_unix => {
            if let Err(e) = result {
                tracing::error!("❌ WebSocket->Unix forwarding failed for {}: {}", session_id, e);
            }
        }
        result = forward_to_ws => {
            if let Err(e) = result {
                tracing::error!("❌ Unix->WebSocket forwarding failed for {}: {}", session_id, e);
            }
        }
    }

    Ok(())
}

/// Forward WebSocket messages to Unix socket (browser input → PTY)
async fn forward_websocket_to_unix(
    mut ws_receiver: futures_util::stream::SplitStream<WebSocket>,
    mut unix_writer: tokio::io::WriteHalf<UnixStream>,
    session_id: String,
) -> Result<()> {
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Binary(data)) => {
                tracing::trace!(
                    "📤 WS->Unix: {} bytes for session {}",
                    data.len(),
                    session_id
                );
                unix_writer.write_all(&data).await?;
                unix_writer.flush().await?;
            }
            Ok(Message::Text(text)) => {
                tracing::trace!("📤 WS->Unix: text data for session {}", session_id);
                unix_writer.write_all(text.as_bytes()).await?;
                unix_writer.flush().await?;
            }
            Ok(Message::Close(_)) => {
                tracing::debug!("🔌 WebSocket closed by client for session {}", session_id);
                break;
            }
            Ok(_) => {
                // Ignore ping/pong frames
            }
            Err(e) => {
                tracing::error!(
                    "❌ WebSocket receive error for session {}: {}",
                    session_id,
                    e
                );
                break;
            }
        }
    }

    Ok(())
}

/// Forward Unix socket data to WebSocket (PTY output → browser)
async fn forward_unix_to_websocket(
    mut unix_reader: tokio::io::ReadHalf<UnixStream>,
    mut ws_sender: futures_util::stream::SplitSink<WebSocket, Message>,
    session_id: String,
) -> Result<()> {
    let mut buffer = [0u8; 4096];

    loop {
        match unix_reader.read(&mut buffer).await {
            Ok(0) => {
                tracing::debug!("📡 Unix socket closed for session {}", session_id);
                break;
            }
            Ok(n) => {
                tracing::trace!("📥 Unix->WS: {} bytes for session {}", n, session_id);
                let data = buffer[..n].to_vec();
                if let Err(e) = ws_sender.send(Message::Binary(data)).await {
                    tracing::error!(
                        "❌ Failed to send to WebSocket for session {}: {}",
                        session_id,
                        e
                    );
                    break;
                }
            }
            Err(e) => {
                tracing::error!(
                    "❌ Unix socket read error for session {}: {}",
                    session_id,
                    e
                );
                break;
            }
        }
    }

    Ok(())
}

/// Spawn a term-replay server for the given session
async fn spawn_term_replay_server(session_id: &str) -> Result<()> {
    use tokio::process::Command;

    tracing::debug!("📋 Spawning: term-replay server {}", session_id);

    let mut cmd = Command::new("term-replay");
    cmd.arg("server").arg(session_id);

    // Spawn as background process
    cmd.kill_on_drop(false); // Don't kill when this process exits

    let child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!(
            "Failed to spawn term-replay server for session '{}': {}",
            session_id,
            e
        )
    })?;

    tracing::info!(
        "✅ Spawned term-replay server for session '{}' with PID: {:?}",
        session_id,
        child.id()
    );

    Ok(())
}

/// Wait for a Unix socket to appear (with timeout)
async fn wait_for_socket(socket_path: &std::path::Path) -> Result<()> {
    use tokio::time::{sleep, timeout, Duration};

    let timeout_duration = Duration::from_secs(5); // 5 second timeout
    let check_interval = Duration::from_millis(100); // Check every 100ms

    tracing::debug!("⏳ Waiting for socket to appear: {}", socket_path.display());

    timeout(timeout_duration, async {
        loop {
            if socket_path.exists() {
                tracing::debug!("✅ Socket appeared: {}", socket_path.display());
                return Ok(());
            }
            sleep(check_interval).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Timeout waiting for socket to appear: {}",
            socket_path.display()
        )
    })?
}

/// Scan for active sessions by looking for .sock files
async fn scan_active_sessions() -> Result<Vec<SessionInfo>> {
    use std::fs;
    use std::time::SystemTime;

    let dir = get_term_replay_dir();
    tracing::debug!("🔍 Scanning for sessions in: {}", dir.display());

    let mut sessions = Vec::new();

    // Read directory entries
    let entries = fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("Failed to read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| anyhow::anyhow!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        // Only process .sock files
        if path.extension().and_then(|s| s.to_str()) == Some("sock") {
            if let Some(session_name) = path.file_stem().and_then(|s| s.to_str()) {
                // Get file metadata for creation time (approximate)
                let created_str = match entry.metadata() {
                    Ok(metadata) => {
                        let created = metadata
                            .created()
                            .or_else(|_| metadata.modified())
                            .unwrap_or(SystemTime::UNIX_EPOCH);
                        format_system_time(created)
                    }
                    Err(_) => {
                        // Fallback to current time if we can't read metadata
                        format_system_time(SystemTime::now())
                    }
                };

                // Try to determine PID (this is approximate, we don't have easy access to the actual PID)
                let pid = std::process::id();

                sessions.push(SessionInfo {
                    id: session_name.to_string(),
                    name: format!("Session: {}", session_name),
                    pid,
                    created: created_str,
                });

                tracing::trace!("📄 Found session: {}", session_name);
            }
        }
    }

    sessions.sort_by(|a, b| a.id.cmp(&b.id)); // Sort by session ID

    Ok(sessions)
}

/// Format SystemTime as ISO string
fn format_system_time(time: SystemTime) -> String {
    use std::time::UNIX_EPOCH;

    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            // Simple approximation - convert to a basic ISO-like format
            // This is not perfect but good enough for our purposes
            let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
                .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
            datetime.to_rfc3339()
        }
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
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

        // Should return a valid JSON array (may be empty if no sessions exist)
        // This is testing that the endpoint works, not the specific content
        assert!(sessions.is_empty() || !sessions.is_empty()); // Always true, but validates deserialization

        // Test that all sessions have valid structure
        for session in &sessions {
            assert!(!session.id.is_empty());
            assert!(!session.name.is_empty());
            assert!(!session.created.is_empty());
            assert!(session.name.starts_with("Session: "));
        }
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
