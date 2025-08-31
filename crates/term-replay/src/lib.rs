use anyhow::Result;
use std::path::PathBuf;

pub async fn run_tunnel_attach(tunnel_socket: &str, session_name: &str) -> Result<()> {
    use tokio::net::{UnixListener, UnixStream};

    println!(
        "🚇 Creating tunnel proxy for remote session: {}",
        session_name
    );
    println!("📡 Tunnel socket: {}", tunnel_socket);

    // Create a local socket for the client to connect to
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);

    // Remove existing socket if it exists
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path)?;
    }

    // Create Unix listener
    let listener = UnixListener::bind(&proxy_socket_path)?;
    println!(
        "✅ Proxy socket created at: {}",
        proxy_socket_path.display()
    );
    println!("🔌 Run: term-replay client -S {}", proxy_socket_name);
    println!("⏳ Waiting for client connection...");

    // Accept connections and proxy them
    while let Ok((client_stream, _)) = listener.accept().await {
        println!("📞 Client connected, establishing tunnel...");

        // Connect to the tunnel socket for each client
        let tunnel_path = term_session::get_socket_path(tunnel_socket);
        if !tunnel_path.exists() {
            eprintln!("❌ Tunnel socket not found: {}", tunnel_path.display());
            continue;
        }

        match UnixStream::connect(&tunnel_path).await {
            Ok(tunnel_stream) => {
                tokio::spawn(handle_tunnel_proxy(
                    client_stream,
                    tunnel_stream,
                    session_name.to_string(),
                ));
            }
            Err(e) => {
                eprintln!("❌ Failed to connect to tunnel: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_tunnel_proxy(
    mut client_stream: tokio::net::UnixStream,
    mut tunnel_stream: tokio::net::UnixStream,
    session_name: String,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    println!("🌉 Proxying connection for session: {}", session_name);

    // Send WebSocket upgrade request to tunnel
    let websocket_request = format!(
        "GET /ws/attach/{} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\r\n",
        session_name
    );

    tunnel_stream
        .write_all(websocket_request.as_bytes())
        .await?;

    // Read WebSocket upgrade response
    let mut response_buffer = vec![0u8; 1024];
    let n = tunnel_stream.read(&mut response_buffer).await?;
    let response = String::from_utf8_lossy(&response_buffer[..n]);

    if !response.contains("101 Switching Protocols") {
        eprintln!("❌ Failed WebSocket upgrade: {}", response);
        return Ok(());
    }

    println!("✅ WebSocket established, starting proxy...");

    // Now just proxy data bidirectionally
    let (mut client_read, mut client_write) = client_stream.split();
    let (mut tunnel_read, mut tunnel_write) = tunnel_stream.split();

    tokio::select! {
        // Client -> Tunnel
        result = tokio::io::copy(&mut client_read, &mut tunnel_write) => {
            match result {
                Ok(n) => println!("🔚 Client->Tunnel finished ({} bytes)", n),
                Err(e) => eprintln!("❌ Client->Tunnel error: {}", e),
            }
        }
        // Tunnel -> Client
        result = tokio::io::copy(&mut tunnel_read, &mut client_write) => {
            match result {
                Ok(n) => println!("🔚 Tunnel->Client finished ({} bytes)", n),
                Err(e) => eprintln!("❌ Tunnel->Client error: {}", e),
            }
        }
    }

    Ok(())
}

pub async fn run_tunnel_list(tunnel_socket: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    println!("🚇 Connecting to tunnel socket: {}", tunnel_socket);

    // Connect to the tunnel socket
    let socket_path = term_session::get_socket_path(tunnel_socket);

    if !socket_path.exists() {
        anyhow::bail!(
            "Tunnel socket not found at {}. Is term-tunnel running?",
            socket_path.display()
        );
    }

    let mut stream = UnixStream::connect(&socket_path).await?;

    // Create HTTP GET request for list-sessions
    let http_request = "GET /list-sessions HTTP/1.1\r\n\
                       Host: localhost\r\n\
                       Connection: close\r\n\r\n";

    // Send HTTP request
    stream.write_all(http_request.as_bytes()).await?;

    // Read the HTTP response
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;

    // Parse HTTP response to extract JSON
    if let Some(json_start) = response.find('[') {
        let json_part = &response[json_start..];

        // Parse and pretty-print the session list
        match serde_json::from_str::<Vec<serde_json::Value>>(json_part) {
            Ok(sessions) => {
                println!("📋 Available remote sessions:");
                for session in sessions {
                    if let (Some(id), Some(name), Some(created)) = (
                        session.get("id").and_then(|v| v.as_str()),
                        session.get("name").and_then(|v| v.as_str()),
                        session.get("created").and_then(|v| v.as_str()),
                    ) {
                        println!("  • {} - {} (created: {})", id, name, created);
                    }
                }
            }
            Err(e) => {
                println!("❌ Failed to parse session list: {}", e);
                println!("Raw response:\n{}", json_part);
            }
        }
    } else {
        anyhow::bail!("Invalid HTTP response: {}", response);
    }

    Ok(())
}

/// Resolve the term-replay binary path from the same directory as the current executable
pub fn resolve_term_replay_binary() -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to get current executable path: {}", e))?;

    let current_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get parent directory of current executable"))?;

    let term_replay_path = current_dir.join("term-replay");

    // Check if the binary exists
    if !term_replay_path.exists() {
        anyhow::bail!(
            "term-replay binary not found at expected path: {}. Please ensure term-replay is in the same directory as the tunnel binary.",
            term_replay_path.display()
        );
    }

    Ok(term_replay_path)
}

/// Run tunnel attach with optional auto-client spawn
pub async fn run_tunnel_attach_with_client(
    tunnel_socket: &str,
    session_name: &str,
    custom_command: Option<&str>,
) -> Result<()> {
    use tokio::net::{UnixListener, UnixStream};

    println!(
        "🚇 Creating tunnel proxy for remote session: {}",
        session_name
    );
    println!("📡 Tunnel socket: {}", tunnel_socket);

    // Create a local socket for the client to connect to
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);

    // Remove existing socket if it exists
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path)?;
    }

    // Create Unix listener
    let listener = UnixListener::bind(&proxy_socket_path)?;
    println!(
        "✅ Proxy socket created at: {}",
        proxy_socket_path.display()
    );

    // Handle auto-client spawn
    match custom_command {
        Some("") => {
            // Empty string means disable auto-spawn
            println!("🔌 Run: term-replay client -S {}", proxy_socket_name);
            println!("⏳ Waiting for client connection...");
        }
        Some(cmd) => {
            // Custom command
            spawn_client_command(cmd, &proxy_socket_name).await?;
        }
        None => {
            // Default: spawn term-replay client from same directory
            spawn_default_client(&proxy_socket_name).await?;
        }
    }

    // Accept connections and proxy them
    while let Ok((client_stream, _)) = listener.accept().await {
        println!("📞 Client connected, establishing tunnel...");

        // Connect to the tunnel socket for each client
        let tunnel_path = term_session::get_socket_path(tunnel_socket);
        if !tunnel_path.exists() {
            eprintln!("❌ Tunnel socket not found: {}", tunnel_path.display());
            continue;
        }

        match UnixStream::connect(&tunnel_path).await {
            Ok(tunnel_stream) => {
                tokio::spawn(handle_tunnel_proxy(
                    client_stream,
                    tunnel_stream,
                    session_name.to_string(),
                ));
            }
            Err(e) => {
                eprintln!("❌ Failed to connect to tunnel: {}", e);
            }
        }
    }

    Ok(())
}

/// Spawn default term-replay client
async fn spawn_default_client(proxy_socket_name: &str) -> Result<()> {
    let term_replay_path = resolve_term_replay_binary()?;

    println!(
        "🚀 Auto-spawning: {} client -S {}",
        term_replay_path.display(),
        proxy_socket_name
    );

    let mut cmd = tokio::process::Command::new(&term_replay_path);
    cmd.arg("client").arg("-S").arg(proxy_socket_name);

    cmd.spawn()?;

    Ok(())
}

/// Spawn custom client command
async fn spawn_client_command(custom_command: &str, proxy_socket_name: &str) -> Result<()> {
    println!(
        "🚀 Auto-spawning: {} client -S {}",
        custom_command, proxy_socket_name
    );

    let mut cmd = tokio::process::Command::new(custom_command);
    cmd.arg("client").arg("-S").arg(proxy_socket_name);

    cmd.spawn()?;

    Ok(())
}
