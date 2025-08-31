use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing;

use term_core::{get_terminal_size, StdinReader, TerminalState, WindowSizeManager};
use term_session::get_socket_path;

/// Client implementation for term-replay
pub async fn run_client(detach_char: u8, session_name: &str) -> Result<()> {
    // Initialize terminal state
    let mut terminal_state = TerminalState::new()?;
    if !terminal_state.is_terminal_available() {
        anyhow::bail!("Attaching to a session requires a terminal.");
    }

    // Get initial window size
    let initial_window_size = get_terminal_size();
    let mut window_manager = WindowSizeManager::new();
    window_manager.update_size(initial_window_size);

    let socket_path = get_socket_path(session_name);

    if !socket_path.exists() {
        anyhow::bail!(
            "Server socket not found at {}. Is the server running? (session: '{}')",
            socket_path.display(),
            session_name
        );
    }

    let stream = UnixStream::connect(&socket_path).await?;
    let (mut server_reader, mut server_writer) = tokio::io::split(stream);

    // Enter raw terminal mode for proper terminal control
    terminal_state.enter_raw_mode()?;

    // Clear screen and position cursor at bottom
    print!("\x1b[H\x1b[J");
    std::io::Write::flush(&mut std::io::stdout())?;

    // Start stdin reader in dedicated thread
    let mut stdin_reader = StdinReader::start()?;

    let mut stdout = tokio::io::stdout();

    // Create tokio signal handlers
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Enhanced client loop with signal handling
    let mut server_buf = [0u8; 1024];

    loop {
        tokio::select! {
            // Handle SIGWINCH directly
            _ = sigwinch.recv() => {
                let new_size = get_terminal_size();
                if window_manager.update_size(new_size) {
                    tracing::debug!("Window size changed: {}x{}", new_size.cols, new_size.rows);

                    // Send window resize escape sequence to server
                    let resize_seq = format!("\x1b[8;{};{}t", new_size.rows, new_size.cols);
                    if let Err(e) = server_writer.write_all(resize_seq.as_bytes()).await {
                        tracing::error!("Failed to send window resize to server: {}", e);
                        break;
                    }
                    if let Err(e) = server_writer.flush().await {
                        tracing::error!("Failed to flush resize sequence: {}", e);
                        break;
                    }
                }
            }

            // Handle shutdown signals directly
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT");
                break;
            }
            _ = sighup.recv() => {
                tracing::info!("Received SIGHUP");
                break;
            }
            // Handle keyboard input from stdin reader
            Some(input_data) = stdin_reader.receiver().recv() => {
                // Check for detach character in input
                if let Some(detach_pos) = input_data.iter().position(|&b| b == detach_char) {
                    // Send any data before the detach key
                    if detach_pos > 0 {
                        if let Err(e) = server_writer.write_all(&input_data[..detach_pos]).await {
                            tracing::error!("Failed to write to server: {}", e);
                        }
                        let _ = server_writer.flush().await;
                    }

                    // Handle detach: show message and exit gracefully
                    print!("\x1b[999H\r\n[detached]\r\n");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    break;
                }

                // No detach key found, send all data to server
                if let Err(e) = server_writer.write_all(&input_data).await {
                    tracing::error!("Failed to write to server: {}", e);
                    break;
                }
                if let Err(e) = server_writer.flush().await {
                    tracing::error!("Failed to flush server writer: {}", e);
                    break;
                }
            }

            // Handle server output
            result = server_reader.read(&mut server_buf) => {
                match result {
                    Ok(0) => {
                        tracing::debug!("Connection to server closed");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = stdout.write_all(&server_buf[..n]).await {
                            tracing::error!("Failed to write to stdout: {}", e);
                            break;
                        }
                        if let Err(e) = stdout.flush().await {
                            tracing::error!("Failed to flush stdout: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading from server: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Shutdown stdin reader gracefully
    if let Err(e) = stdin_reader.shutdown().await {
        tracing::warn!("Failed to shutdown stdin reader: {}", e);
    }

    // Terminal state will be automatically restored by Drop trait

    Ok(())
}
