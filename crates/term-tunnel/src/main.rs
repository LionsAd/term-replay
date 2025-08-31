use anyhow::Result;
use clap::Parser;
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tracing;

use term_core::{create_new_pty_with_command, get_terminal_size, TerminalState, WindowSizeManager};
use term_protocol::handshake::TUNNEL_READY_SEQUENCE;
use term_session::get_socket_path;

#[derive(Parser)]
#[command(author, version, about = "Terminal tunnel client for remote sessions", long_about = None)]
struct Cli {
    /// Set the socket name (default: term-tunnel). Creates /tmp/{name}.sock
    #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
    socket_name: Option<String>,

    /// Custom command to run (default: login bash). Same logic as term-replay server.
    #[arg(value_name = "COMMAND")]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let cli = Cli::parse();

    let socket_name = cli.socket_name.unwrap_or_else(|| "term-tunnel".to_string());
    let command = if cli.command.is_empty() {
        vec!["bash".to_string(), "-l".to_string()] // Same default as term-replay server
    } else {
        cli.command
    };

    run_tunnel_client(&socket_name, &command).await
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
        run_tunnel_mode(&pty_async, socket_name).await?;
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

/// Phase 2: Run in tunnel mode with smux multiplexing (placeholder for now)
async fn run_tunnel_mode(
    _pty_async: &tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    socket_name: &str,
) -> Result<()> {
    tracing::info!("🌉 Entering tunnel mode - creating Unix socket");

    let socket_path = get_socket_path(socket_name);

    // Remove existing socket if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let _listener = UnixListener::bind(&socket_path)?;
    tracing::info!("🔌 Listening on: {}", socket_path.display());

    // TODO: Implement smux multiplexing in next phase
    // For now, just create the socket and wait
    tracing::info!("⏳ Tunnel mode placeholder - socket created successfully");
    tracing::info!("💡 Ready for smux implementation in next phase!");

    // Keep socket alive for a moment to verify it works
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Clean up socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
        tracing::debug!("🧹 Cleaned up socket: {}", socket_path.display());
    }

    Ok(())
}
