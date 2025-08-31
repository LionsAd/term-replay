use anyhow::Result;
use clap::{Parser, Subcommand};

// Import from our extracted crates
use term_client::run_client;
use term_protocol::parse_detach_char;
use term_server::run_server;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the persistent terminal server
    Server {
        /// Set the socket name (default: term-replay). Creates {name}.sock and {name}.log
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
        /// Custom command to run instead of bash (default: ["bash"])
        #[arg(value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Attach to the persistent terminal server
    Client {
        /// Set the detach character (default: Ctrl-\). Use '^?' for DEL, '^X' for Ctrl-X
        #[arg(short = 'e', long = "escape", value_name = "CHAR")]
        detach_char: Option<String>,
        /// Set the socket name (default: term-replay). Connects to {name}.sock
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
    },
    /// Tunnel commands for remote session access
    Tunnel {
        #[command(subcommand)]
        tunnel_command: TunnelCommands,
    },
}

#[derive(Subcommand)]
enum TunnelCommands {
    /// Attach to a remote session through tunnel
    Attach {
        /// Set the socket name (default: term-tunnel). Connects to {name}.sock
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
        /// Session to attach to (default: term-replay)
        #[arg(value_name = "SESSION")]
        session: Option<String>,
    },
    /// List available remote sessions through tunnel
    List {
        /// Set the socket name (default: term-tunnel). Connects to {name}.sock
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging based on environment variables
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "error".to_string());

    tracing_subscriber::fmt().with_env_filter(log_level).init();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Server {
            socket_name,
            command,
        } => {
            let session_name = socket_name.unwrap_or_else(|| "term-replay".to_string());
            let cmd = if command.is_empty() {
                vec!["bash".to_string(), "-l".to_string()]
            } else {
                command
            };
            run_server(&session_name, &cmd).await
        }
        Commands::Client {
            detach_char,
            socket_name,
        } => {
            let detach_byte = if let Some(char_str) = detach_char {
                parse_detach_char(&char_str)?
            } else {
                0x1C // Default: Ctrl-\
            };
            let session_name = socket_name.unwrap_or_else(|| "term-replay".to_string());
            run_client(detach_byte, &session_name).await
        }
        Commands::Tunnel { tunnel_command } => match tunnel_command {
            TunnelCommands::Attach {
                socket_name,
                session,
            } => {
                let tunnel_socket = socket_name.unwrap_or_else(|| "term-tunnel".to_string());
                let session_name = session.unwrap_or_else(|| "term-replay".to_string());
                run_tunnel_attach(&tunnel_socket, &session_name).await
            }
            TunnelCommands::List { socket_name } => {
                let tunnel_socket = socket_name.unwrap_or_else(|| "term-tunnel".to_string());
                run_tunnel_list(&tunnel_socket).await
            }
        },
    };

    result
}

/// Attach to a remote session through the tunnel by creating a local proxy socket
async fn run_tunnel_attach(tunnel_socket: &str, session_name: &str) -> Result<()> {
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

/// Handle proxying between client and tunnel
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

/// List available remote sessions through the tunnel
async fn run_tunnel_list(tunnel_socket: &str) -> Result<()> {
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
