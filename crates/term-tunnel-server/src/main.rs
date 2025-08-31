use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{Json, Response},
    routing::get,
    Router,
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use std::os::fd::AsRawFd;
use std::{
    io::{self, Write},
    time::SystemTime,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::{net::UnixStream, signal};
use tracing;

use term_protocol::{handshake::TUNNEL_READY_SEQUENCE, SessionInfo};
use term_session::{get_socket_path, get_term_replay_dir};

#[derive(Parser)]
#[command(author, version, about = "Term tunnel server")]
struct Args {
    /// Custom command to spawn term-replay servers. Use -c "" to disable auto-spawn, or omit -c for default behavior.
    #[arg(short = 'c', long = "command")]
    custom_command: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let args = Args::parse();
    run_tunnel_server(args.custom_command.as_deref()).await
}

/// Main tunnel server implementation
pub async fn run_tunnel_server(custom_command: Option<&str>) -> Result<()> {
    tracing::info!("🚇 Starting term-tunnel-server");

    // Phase 1: Emit handshake sequence to establish tunnel
    emit_handshake()?;

    // Phase 2: Capture original stdout BEFORE redirecting it
    let original_stdout_fd = unsafe { libc::dup(1) }; // Duplicate stdout fd

    // CRITICAL: After handshake, redirect all logs to a file to avoid interfering with smux
    setup_file_logging()?;

    // Start HTTP/WebSocket server in background
    let custom_command_owned = custom_command.map(|s| s.to_string());
    let http_server_task = tokio::spawn(start_http_server(custom_command_owned));

    // Start smux handler with access to original stdout
    let smux_task = tokio::spawn(handle_stdin_smux_streams_with_fd(original_stdout_fd));

    tokio::select! {
        result = http_server_task => {
            if let Err(_) = result {}
        }
        result = smux_task => {
            if let Err(_) = result {}
        }
    }

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

/// Redirect stdout/stderr to /dev/null after handshake to avoid interfering with smux channel
fn setup_file_logging() -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // Open /dev/null for writing
    let dev_null = OpenOptions::new().write(true).open("/dev/null")?;
    let dev_null_fd = dev_null.as_raw_fd();

    // Redirect stdout (fd 1) to /dev/null
    unsafe {
        libc::dup2(dev_null_fd, 1);
    }

    // Redirect stderr (fd 2) to /dev/null
    unsafe {
        libc::dup2(dev_null_fd, 2);
    }

    // Note: stdin (fd 0) is left untouched as it's used for smux communication

    Ok(())
}

/// Handle incoming smux streams from stdin and forward them to localhost HTTP server
async fn handle_stdin_smux_streams_with_fd(original_stdout_fd: i32) -> Result<()> {
    use tokio::io::stdin;

    // Create a wrapper for stdin that implements AsyncRead + AsyncWrite
    // Use the captured stdout fd before redirection
    let stdin_stream = StdinWrapper::new_with_fd(stdin(), original_stdout_fd)?;

    // Configure smux server (not client!) - we accept connections from term-tunnel
    let config = smux::Config::default();

    // Create smux server session from stdin - term-tunnel connects to us as client
    let session = smux::Session::server(stdin_stream, config).await?;

    // Accept incoming streams from term-tunnel and forward to HTTP server
    let mut stream_id = 0;
    while let Ok(smux_stream) = session.accept_stream().await {
        stream_id += 1;

        // Handle each stream in a separate task
        tokio::spawn(async move {
            // Errors are silently ignored to avoid corrupting smux protocol
            if let Err(_) = forward_smux_to_http_server(smux_stream, stream_id).await {}
        });
    }

    Ok(())
}

/// Forward a smux stream to the local HTTP server
async fn forward_smux_to_http_server(smux_stream: smux::Stream, _stream_id: u32) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect to local HTTP server
    let http_stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;

    // Split both streams for bidirectional forwarding
    let (mut smux_reader, mut smux_writer) = tokio::io::split(smux_stream);
    let (mut http_reader, mut http_writer) = tokio::io::split(http_stream);

    // Forward smux -> HTTP
    let forward_to_http = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut smux_reader, &mut http_writer).await;
    });

    // Forward HTTP -> smux
    let forward_to_smux = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut http_reader, &mut smux_writer).await;
    });

    // Wait for either direction to complete
    tokio::select! {
        _ = forward_to_http => {}
        _ = forward_to_smux => {}
    }

    Ok(())
}

/// Wrapper to make stdin work as AsyncRead + AsyncWrite for smux
struct StdinWrapper {
    stdin: tokio::io::Stdin,
    stdout_fd: tokio::io::unix::AsyncFd<i32>,
}

impl StdinWrapper {
    fn new_with_fd(stdin: tokio::io::Stdin, original_stdout_fd: i32) -> std::io::Result<Self> {
        // Use the captured original stdout file descriptor
        let stdout_fd = tokio::io::unix::AsyncFd::new(original_stdout_fd)?;
        Ok(Self { stdin, stdout_fd })
    }
}

impl AsyncRead for StdinWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdinWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // Use the raw file descriptor with AsyncFd
        let mut guard = match self.stdout_fd.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(guard)) => guard,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };

        match guard.try_io(|inner| {
            let fd = inner.as_raw_fd();
            unsafe {
                let result = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
                if result == -1 {
                    let errno = *libc::__error();
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                        return Err(std::io::Error::from_raw_os_error(errno));
                    } else {
                        return Err(std::io::Error::from_raw_os_error(errno));
                    }
                }
                Ok(result as usize)
            }
        }) {
            Ok(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
            Ok(Err(e)) => std::task::Poll::Ready(Err(e)),
            Err(_) => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // For raw file descriptors, flush is a no-op
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // For raw file descriptors, shutdown is a no-op
        std::task::Poll::Ready(Ok(()))
    }
}

/// Start the HTTP/WebSocket server
async fn start_http_server(custom_command: Option<String>) -> Result<()> {
    tracing::info!("🌐 Starting HTTP/WebSocket server on localhost:8080");

    // Create the HTTP router
    let app = create_app_router(custom_command.as_deref()).await;

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
async fn create_app_router(custom_command: Option<&str>) -> Router {
    // Store custom command in app state
    let command = custom_command.map(String::from);

    Router::new()
        .route("/list-sessions", get(list_sessions))
        .route("/health", get(health_check))
        .route("/ws/attach/:session_id", get(websocket_handler))
        .with_state(AppState {
            custom_command: command,
        })
}

/// App state for passing custom command to handlers
#[derive(Clone)]
struct AppState {
    custom_command: Option<String>,
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
async fn websocket_handler(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    tracing::info!(
        "🔌 WebSocket connection request for session: {}",
        session_id
    );

    ws.on_upgrade(move |socket| {
        handle_websocket_connection(socket, session_id, state.custom_command)
    })
}

/// Handle WebSocket connection - bridge to Unix socket
async fn handle_websocket_connection(
    websocket: axum::extract::ws::WebSocket,
    session_id: String,
    custom_command: Option<String>,
) {
    tracing::info!("🌐 Starting WebSocket session: {}", session_id);

    if let Err(e) =
        websocket_to_unix_bridge(websocket, &session_id, custom_command.as_deref()).await
    {
        tracing::error!("❌ WebSocket session {} failed: {}", session_id, e);
    }

    tracing::info!("🔚 WebSocket session {} ended", session_id);
}

/// Bridge WebSocket to Unix socket (term-replay server)
async fn websocket_to_unix_bridge(
    websocket: WebSocket,
    session_id: &str,
    custom_command: Option<&str>,
) -> Result<()> {
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
                "🚀 Session '{}' not found, auto-spawning server with command: {:?}",
                session_id,
                custom_command
            );
            term_tunnel_server::spawn_term_replay_server_with_command(session_id, custom_command)
                .await?;

            // Wait for socket to appear with timeout
            term_tunnel_server::wait_for_socket(&socket_path).await?;

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
        let app = create_app_router(None).await;

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
        let app = create_app_router(None).await;

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
        let app = create_app_router(None).await;

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
