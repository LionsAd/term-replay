use anyhow::Result;
use clap::{Parser, Subcommand};
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncWriteExt;
use tracing;

use term_core::{create_new_pty_with_command, get_terminal_size, TerminalState, WindowSizeManager};
use term_protocol::handshake::TUNNEL_READY_SEQUENCE;
use term_session::get_socket_path;

#[derive(Parser)]
#[command(author, version, about = "Terminal tunnel client for remote sessions", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Set the socket name (default: term-tunnel). Creates /tmp/{name}.sock
    #[arg(short = 'S', long = "socket-name", value_name = "NAME", global = true)]
    socket_name: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Attach to a remote session through tunnel
    Attach {
        /// Session to attach to (default: term-replay)
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Custom command to spawn client. Use -c "" to disable auto-spawn, or omit -c for default behavior.
        #[arg(short = 'c', long = "command")]
        custom_command: Option<String>,
    },
    /// List available remote sessions through tunnel
    List,
    /// Start tunnel (legacy mode - default when no subcommand given)
    Start {
        /// Custom command to run (default: login bash). Same logic as term-replay server.
        #[arg(value_name = "COMMAND")]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let cli = Cli::parse();
    let socket_name = cli.socket_name.unwrap_or_else(|| "term-tunnel".to_string());

    match cli.command.unwrap_or(Commands::Start { command: vec![] }) {
        Commands::Attach {
            session,
            custom_command,
        } => {
            let session_name = session.unwrap_or_else(|| "term-replay".to_string());
            term_tunnel::run_tunnel_attach(&socket_name, &session_name, custom_command.as_deref())
                .await
        }
        Commands::List => term_tunnel::run_tunnel_list(&socket_name).await,
        Commands::Start { command } => {
            let cmd = if command.is_empty() {
                vec!["bash".to_string(), "-l".to_string()] // Same default as term-replay server
            } else {
                command
            };
            run_tunnel_client(&socket_name, &cmd).await
        }
    }
}

/// Main tunnel client implementation
pub async fn run_tunnel_client(socket_name: &str, command: &[String]) -> Result<()> {
    tracing::info!("🚇 Starting term-tunnel client");
    tracing::info!("Socket: /tmp/{}.sock", socket_name);
    tracing::info!("Command: {}", command.join(" "));

    // Initialize terminal state
    let mut terminal_state = TerminalState::new()?;
    let initial_window_size = get_terminal_size();
    let mut window_manager = WindowSizeManager::new();
    window_manager.update_size(initial_window_size);

    // Enter raw mode for proper terminal control
    if terminal_state.is_terminal_available() {
        terminal_state.enter_raw_mode()?;
        tracing::debug!("✅ Entered raw terminal mode");
    }

    // Create PTY and spawn command (same logic as term-replay server)
    let (pty_master, child_pid) = create_new_pty_with_command(command)?;
    let pty_fd = pty_master.as_raw_fd();
    tracing::info!("🎯 Created PTY with PID: {}, FD: {}", child_pid, pty_fd);

    // Apply window size to PTY
    window_manager.apply_to_fd(pty_fd)?;

    // Make PTY non-blocking
    nix::fcntl::fcntl(
        pty_fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )?;

    // Create async wrapper for PTY
    let pty_async = tokio::io::unix::AsyncFd::new(pty_master)?;

    // Phase 1: Normal terminal passthrough until handshake
    let handshake_detected = run_terminal_mode(&pty_async, &terminal_state).await?;

    if handshake_detected {
        tracing::info!("🤝 Handshake detected! Switching to tunnel mode...");

        // Phase 2: Switch to tunnel mode (smux multiplexing)
        run_tunnel_mode(pty_async, socket_name).await?;
    } else {
        tracing::info!("🔚 Command completed without handshake");
    }

    // Terminal state will be automatically restored by Drop trait
    tracing::info!("🚇 term-tunnel client exiting");
    Ok(())
}

/// Phase 1: Run in normal terminal mode until handshake is detected
async fn run_terminal_mode(
    pty_async: &tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    _terminal_state: &TerminalState,
) -> Result<bool> {
    tracing::debug!("📺 Entering terminal passthrough mode");

    let mut handshake_buffer = Vec::new();
    let mut stdout = tokio::io::stdout();

    // Create stdin reader for terminal input
    let mut stdin_reader = term_core::StdinReader::start()?;

    let mut pty_buf = [0u8; 1024];
    let mut handshake_found = false;

    loop {
        tokio::select! {
            // Handle PTY output (look for handshake sequence)
            result = pty_async.readable() => {
                let mut guard = result?;
                match guard.try_io(|inner| {
                    let fd = inner.as_raw_fd();
                    unsafe {
                        let result = libc::read(fd, pty_buf.as_mut_ptr() as *mut libc::c_void, pty_buf.len());
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
                    Ok(Ok(0)) => {
                        tracing::debug!("📟 PTY EOF - command exited");
                        break;
                    }
                    Ok(Ok(n)) => {
                        let data = &pty_buf[..n];

                        // Add to handshake buffer and check for sequence
                        handshake_buffer.extend_from_slice(data);

                        // Look for handshake sequence in buffer
                        if let Some(pos) = handshake_buffer
                            .windows(TUNNEL_READY_SEQUENCE.len())
                            .position(|window| window == TUNNEL_READY_SEQUENCE)
                        {
                            tracing::info!("🎉 Found handshake sequence at position {}", pos);

                            // Output everything before handshake to terminal
                            if pos > 0 {
                                stdout.write_all(&handshake_buffer[..pos]).await?;
                                stdout.flush().await?;
                            }

                            // Don't output the handshake sequence itself
                            handshake_found = true;
                            break;
                        }

                        // If buffer gets too large without finding handshake, output and reset
                        if handshake_buffer.len() > TUNNEL_READY_SEQUENCE.len() * 2 {
                            let split_point = handshake_buffer.len() - TUNNEL_READY_SEQUENCE.len() + 1;
                            stdout.write_all(&handshake_buffer[..split_point]).await?;
                            stdout.flush().await?;
                            handshake_buffer.drain(..split_point);
                        }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Not ready yet, continue
                        continue;
                    }
                    Ok(Err(e)) => {
                        tracing::error!("PTY read error: {}", e);
                        return Err(e.into());
                    }
                    Err(_) => {
                        // Not ready yet, continue
                        continue;
                    }
                }
            }

            // Handle terminal input (forward to PTY)
            input = stdin_reader.receiver().recv() => {
                if let Some(data) = input {
                    // Forward input to PTY
                    let mut guard = pty_async.writable().await?;
                    match guard.try_io(|inner| {
                        let fd = inner.as_raw_fd();
                        unsafe {
                            let result = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
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
                        Ok(Ok(_)) => {}, // Success
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue; // Retry later
                        }
                        Ok(Err(e)) => {
                            tracing::error!("PTY write error: {}", e);
                            return Err(e.into());
                        }
                        Err(_) => {
                            continue; // Not ready, retry
                        }
                    }
                }
            }

            // Handle Ctrl+C gracefully
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received Ctrl+C, exiting");
                break;
            }
        }
    }

    // Shutdown stdin reader
    stdin_reader.shutdown().await?;

    // Output any remaining buffered data (except handshake sequence)
    if !handshake_found && !handshake_buffer.is_empty() {
        stdout.write_all(&handshake_buffer).await?;
        stdout.flush().await?;
    }

    Ok(handshake_found)
}

/// Phase 2: Run in tunnel mode with smux multiplexing
async fn run_tunnel_mode(
    pty_async: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    socket_name: &str,
) -> Result<()> {
    tracing::info!("🌉 Entering tunnel mode - creating Unix socket");

    let socket_path = get_socket_path(socket_name);

    // Remove existing socket if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Create Unix socket listener for external connections
    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!("🔌 Tunnel socket listening at: {}", socket_path.display());

    // Create smux session from PTY
    let pty_stream = create_pty_stream(pty_async).await?;
    let session = smux::Session::server(pty_stream, smux::Config::default()).await?;
    tracing::info!("🎯 Created smux server session");

    // Handle both Unix socket connections AND smux streams concurrently
    let mut connection_id = 0;
    loop {
        tokio::select! {
            // Accept Unix socket connections
            result = listener.accept() => {
                match result {
                    Ok((unix_stream, _)) => {
                        connection_id += 1;
                        tracing::info!("🔌 New Unix socket connection #{}", connection_id);

                        let conn_id = connection_id;
                        tokio::spawn(async move {
                            if let Err(e) = handle_unix_connection(unix_stream, conn_id).await {
                                tracing::error!("Unix connection #{} error: {}", conn_id, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept Unix connection: {}", e);
                    }
                }
            }

            // Accept new smux streams from the session (ORIGINAL UNCHANGED)
            result = session.accept_stream() => {
                match result {
                    Ok(smux_stream) => {
                        connection_id += 1;
                        tracing::info!("📡 New smux stream #{}", connection_id);

                        // Handle this stream in a separate task
                        let conn_id = connection_id;
                        tokio::spawn(async move {
                            if let Err(e) = handle_smux_stream(smux_stream, conn_id).await {
                                tracing::error!("Smux stream #{} error: {}", conn_id, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept smux stream: {}", e);
                        break;
                    }
                }
            }

            // Handle shutdown signals
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("🛑 Received shutdown signal, closing tunnel");
                break;
            }
        }
    }

    // Clean up socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
        tracing::debug!("🧹 Cleaned up socket: {}", socket_path.display());
    }

    Ok(())
}

/// Create a tokio stream wrapper for the PTY
async fn create_pty_stream(
    pty_async: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
) -> Result<PtyStream> {
    Ok(PtyStream::new(pty_async))
}

/// Handle a Unix socket connection - for now just echo back what we receive
async fn handle_unix_connection(
    mut unix_stream: tokio::net::UnixStream,
    conn_id: u32,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::info!("🌊 Handling Unix connection #{}", conn_id);

    let mut buffer = [0u8; 4096];
    loop {
        match unix_stream.read(&mut buffer).await {
            Ok(0) => {
                tracing::info!("🔚 Connection #{} closed by client", conn_id);
                break;
            }
            Ok(n) => {
                tracing::trace!("📡 Connection #{}: received {} bytes", conn_id, n);
                // For now, just echo back what we received
                if let Err(e) = unix_stream.write_all(&buffer[..n]).await {
                    tracing::error!("Connection #{} write error: {}", conn_id, e);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("Connection #{} read error: {}", conn_id, e);
                break;
            }
        }
    }

    tracing::info!("🔚 Connection #{} handler finished", conn_id);
    Ok(())
}

/// Handle a single smux stream (ORIGINAL FUNCTION RESTORED)
async fn handle_smux_stream(_smux_stream: smux::Stream, conn_id: u32) -> Result<()> {
    tracing::info!("🌊 Starting stream handler for smux stream #{}", conn_id);

    // For now, just echo data back to demonstrate the stream is working
    // In a real implementation, this would connect to the Unix socket
    // and forward data bidirectionally

    tracing::info!(
        "📡 Smux stream #{} active - placeholder implementation",
        conn_id
    );

    // Keep the stream alive briefly for testing
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    tracing::info!("🔚 Smux stream #{} closed", conn_id);
    Ok(())
}

/// Wrapper to make PTY compatible with smux as an AsyncRead + AsyncWrite stream
struct PtyStream {
    pty_async: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
}

impl PtyStream {
    fn new(pty_async: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>) -> Self {
        Self { pty_async }
    }
}

impl tokio::io::AsyncRead for PtyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = match self.pty_async.poll_read_ready(cx) {
            std::task::Poll::Ready(Ok(guard)) => guard,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };

        match guard.try_io(|inner| {
            let fd = inner.as_raw_fd();
            let buf_slice = buf.initialize_unfilled();
            unsafe {
                let result = libc::read(
                    fd,
                    buf_slice.as_mut_ptr() as *mut libc::c_void,
                    buf_slice.len(),
                );
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
            Ok(Ok(n)) => {
                buf.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
            Ok(Err(e)) => std::task::Poll::Ready(Err(e)),
            Err(_) => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for PtyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let mut guard = match self.pty_async.poll_write_ready(cx) {
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
        // PTY doesn't need explicit flushing
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // PTY shutdown is handled by the Drop trait
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_sequence_constant() {
        // Verify the handshake sequence is correct
        assert_eq!(TUNNEL_READY_SEQUENCE, b"\x1b]tunnel-ready;\x07");
        assert_eq!(TUNNEL_READY_SEQUENCE.len(), 16);
    }

    #[tokio::test]
    async fn test_handshake_detection_in_single_buffer() {
        // Simulate handshake sequence in a single read
        let handshake_data = b"Starting server...\x1b]tunnel-ready;\x07Server ready";
        let mut handshake_buffer = Vec::new();
        handshake_buffer.extend_from_slice(handshake_data);

        let pos = handshake_buffer
            .windows(TUNNEL_READY_SEQUENCE.len())
            .position(|window| window == TUNNEL_READY_SEQUENCE);

        assert_eq!(pos, Some(18)); // Position after "Starting server..."
    }

    #[tokio::test]
    async fn test_handshake_detection_split_across_buffers() {
        // Simulate handshake sequence split across multiple reads
        let mut handshake_buffer = Vec::new();

        // First chunk - partial handshake
        handshake_buffer.extend_from_slice(b"Starting server...\x1b]tunnel-");

        // Check no false positive
        let pos = handshake_buffer
            .windows(TUNNEL_READY_SEQUENCE.len())
            .position(|window| window == TUNNEL_READY_SEQUENCE);
        assert_eq!(pos, None);

        // Second chunk - complete handshake
        handshake_buffer.extend_from_slice(b"ready;\x07Server ready");

        let pos = handshake_buffer
            .windows(TUNNEL_READY_SEQUENCE.len())
            .position(|window| window == TUNNEL_READY_SEQUENCE);
        assert_eq!(pos, Some(18));
    }

    #[tokio::test]
    async fn test_handshake_detection_no_false_positives() {
        // Test similar but incorrect sequences
        let test_cases: Vec<&[u8]> = vec![
            b"\\x1b]tunnel-ready;\\x07", // Escaped sequences
            b"\x1b]tunnel-ready;\x06",   // Wrong ending byte
            b"\x1a]tunnel-ready;\x07",   // Wrong starting byte
            b"\x1b[tunnel-ready;\x07",   // Wrong bracket
            b"\x1b]tunnel-ready\x07",    // Missing semicolon
            b"tunnel-ready",             // Partial sequence
        ];

        for test_data in test_cases {
            let mut handshake_buffer = Vec::new();
            handshake_buffer.extend_from_slice(test_data);

            let pos = handshake_buffer
                .windows(TUNNEL_READY_SEQUENCE.len())
                .position(|window| window == TUNNEL_READY_SEQUENCE);

            assert_eq!(pos, None, "False positive for: {:?}", test_data);
        }
    }

    #[tokio::test]
    async fn test_handshake_detection_multiple_occurrences() {
        // Test finding first occurrence when multiple exist
        let data = b"prefix\x1b]tunnel-ready;\x07middle\x1b]tunnel-ready;\x07suffix";
        let mut handshake_buffer = Vec::new();
        handshake_buffer.extend_from_slice(data);

        let pos = handshake_buffer
            .windows(TUNNEL_READY_SEQUENCE.len())
            .position(|window| window == TUNNEL_READY_SEQUENCE);

        assert_eq!(pos, Some(6)); // First occurrence position
    }

    #[tokio::test]
    async fn test_handshake_buffer_overflow_protection() {
        // Test the buffer overflow protection logic
        let large_data = b"A".repeat(100);
        let mut handshake_buffer = Vec::new();
        handshake_buffer.extend_from_slice(&large_data);

        // Simulate the overflow protection from run_terminal_mode
        let max_size = TUNNEL_READY_SEQUENCE.len() * 2;
        if handshake_buffer.len() > max_size {
            let split_point = handshake_buffer.len() - TUNNEL_READY_SEQUENCE.len() + 1;
            handshake_buffer.drain(..split_point);
        }

        // Buffer should be reduced to manageable size
        assert!(handshake_buffer.len() <= TUNNEL_READY_SEQUENCE.len());
    }

    #[tokio::test]
    async fn test_handshake_edge_case_exact_boundary() {
        // Test handshake at exact buffer boundaries
        let mut handshake_buffer = Vec::new();

        // Add exactly the sequence
        handshake_buffer.extend_from_slice(TUNNEL_READY_SEQUENCE);

        let pos = handshake_buffer
            .windows(TUNNEL_READY_SEQUENCE.len())
            .position(|window| window == TUNNEL_READY_SEQUENCE);

        assert_eq!(pos, Some(0)); // Found at beginning
    }
}
