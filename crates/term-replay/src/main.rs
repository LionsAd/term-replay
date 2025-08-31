use anyhow::Result;
use clap::{Parser, Subcommand};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::{File as TokioFile, OpenOptions};
use tokio::io::{unix::AsyncFd, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tracing;

// Import from our extracted crates
use term_core::{
    apply_window_size_to_pty, create_new_pty_with_command, get_terminal_size, SignalManager,
    StdinReader, TerminalState, WindowSizeManager,
};
use term_protocol::{
    constants::{DEBUG_RAW_LOGGING, INPUT_LOGGING},
    parse_detach_char,
};
use term_session::{
    get_debug_raw_log_path, get_input_log_path, get_log_path, get_socket_path, pty_reader_task,
    InputParser, PtyOutput,
};

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
}

// SERVER LOGIC
async fn server_main(session_name: &str, command: &[String]) -> Result<()> {
    // Initialize signal manager for server mode
    let signal_manager = SignalManager::new(false);
    signal_manager.setup_server_signals()?;

    // Initialize window size manager with defaults for server
    let window_manager = WindowSizeManager::new();

    // Generate paths for this session
    let socket_path = get_socket_path(session_name);
    let log_path = get_log_path(session_name);
    let debug_raw_log_path = get_debug_raw_log_path(session_name);
    let input_log_path = get_input_log_path(session_name);

    // Check if session already exists
    if socket_path.exists() {
        anyhow::bail!(
            "Session '{}' already exists (socket: {}). Please choose a different name or stop the existing session.",
            session_name,
            socket_path.display()
        );
    }

    // Clean up debug and input logs from previous runs (preserve main log)
    if DEBUG_RAW_LOGGING && debug_raw_log_path.exists() {
        std::fs::remove_file(&debug_raw_log_path)?;
    }
    if INPUT_LOGGING && input_log_path.exists() {
        std::fs::remove_file(&input_log_path)?;
    }

    // Spawn zombie reaper task
    tokio::spawn(async move {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigchld_stream =
            signal(SignalKind::child()).expect("Failed to create SIGCHLD listener");

        tracing::debug!("🧟 Zombie reaper task started - listening for SIGCHLD");

        while sigchld_stream.recv().await.is_some() {
            tracing::debug!("📢 Received SIGCHLD - reaping zombie children");

            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, status)) => {
                        tracing::info!(
                            "🧟 Reaped zombie child process {} with exit status {}",
                            pid,
                            status
                        );
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) => {
                        tracing::info!(
                            "🧟 Reaped zombie child process {} killed by signal {}",
                            pid,
                            sig
                        );
                    }
                    Ok(WaitStatus::StillAlive) => {
                        tracing::debug!("✅ No more zombie children to reap");
                        break;
                    }
                    Err(nix::errno::Errno::ECHILD) => {
                        tracing::debug!("ℹ️  No child processes exist");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("❌ Error in waitpid: {}", e);
                        break;
                    }
                    _ => {
                        tracing::debug!("🔄 Other wait status encountered, continuing");
                    }
                }
            }
        }
        tracing::debug!("🧟 Zombie reaper task exiting");
    });

    let listener = UnixListener::bind(&socket_path)?;
    let log_file = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?,
    ));

    // Debug raw log file (logs ALL data, unfiltered)
    let debug_raw_log = if DEBUG_RAW_LOGGING {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_raw_log_path)
                .await?,
        )))
    } else {
        None
    };

    // Input log file (logs client-to-PTY data)
    let input_log = if INPUT_LOGGING {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&input_log_path)
                .await?,
        )))
    } else {
        None
    };

    // Broadcast channel to send PTY output to all connected clients
    let (tx, _) = broadcast::channel::<PtyOutput>(1024);

    // Track PTY state - None when no PTY exists, Some when PTY is active
    let pty_async: Arc<Mutex<Option<Arc<AsyncFd<std::os::unix::io::OwnedFd>>>>> =
        Arc::new(Mutex::new(None));

    // Flag to prevent multiple concurrent PTY creation attempts
    let pty_creating = Arc::new(tokio::sync::Semaphore::new(1));

    // Main Accept Loop with Signal Handling
    tracing::info!("Server listening on {}", socket_path.display());
    loop {
        // Check for shutdown signal
        if signal_manager.check_shutdown_requested() {
            if let Some(sig) = signal_manager.get_shutdown_signal() {
                tracing::info!("Received shutdown signal: {:?}, terminating server", sig);
            }

            // Clean up socket file before shutdown
            if socket_path.exists() {
                if let Err(e) = std::fs::remove_file(&socket_path) {
                    tracing::warn!(
                        "Failed to remove socket file {}: {}",
                        socket_path.display(),
                        e
                    );
                } else {
                    tracing::debug!("Cleaned up socket file: {}", socket_path.display());
                }
            }

            return Ok(());
        }

        tokio::select! {
            // Accept new client connections
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        tracing::info!("🔌 New client connected from {:?}", addr);

                        // Check if we need to create a PTY
                        let needs_pty = {
                            let pty_guard = pty_async.lock().await;
                            let has_pty = pty_guard.is_some();
                            tracing::debug!("📊 PTY check: has_pty={}", has_pty);
                            pty_guard.is_none()
                        };

                        if needs_pty {
                            tracing::info!("🚀 No PTY exists, attempting to create new PTY with command...");

                            // Use semaphore to ensure only one PTY creation at a time
                            if let Ok(_permit) = pty_creating.try_acquire() {
                                tracing::debug!("🔒 Acquired PTY creation semaphore");

                                // Double-check PTY still doesn't exist (race condition protection)
                                let still_needs_pty = {
                                    let pty_guard = pty_async.lock().await;
                                    let needs = pty_guard.is_none();
                                    tracing::debug!("🔄 Double-check PTY needed: {}", needs);
                                    needs
                                };

                                if still_needs_pty {
                                    tracing::info!("✅ Confirmed PTY creation needed, creating new PTY with command: {}", command.join(" "));

                                    // Create new PTY with custom command
                                    match create_new_pty_with_command(command) {
                                        Ok((pty_master, child_pid)) => {
                                            let pty_master_fd = pty_master.as_raw_fd();
                                            tracing::info!("🎯 SUCCESS: Created PTY with command, PID: {}, FD: {}",
                                                child_pid, pty_master_fd);

                                            // Make PTY non-blocking
                                            tracing::debug!("⚙️  Making PTY fd {} non-blocking...", pty_master_fd);
                                            nix::fcntl::fcntl(
                                                pty_master_fd,
                                                nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
                                            )?;

                                            // Apply window size
                                            tracing::debug!("📐 Applying window size to PTY fd {}...", pty_master_fd);
                                            window_manager.apply_to_fd(pty_master_fd)?;

                                            // Create async wrapper
                                            tracing::debug!("🔄 Creating AsyncFd wrapper for PTY fd {}...", pty_master_fd);
                                            let pty_async_fd = Arc::new(AsyncFd::new(pty_master)?);

                                            // Store in shared state
                                            {
                                                tracing::debug!("💾 Storing PTY in shared state...");
                                                let mut pty_guard = pty_async.lock().await;
                                                *pty_guard = Some(pty_async_fd.clone());
                                                tracing::debug!("✅ PTY stored in shared state successfully");
                                            }

                                            // Start PTY reader task
                                            tracing::info!("🚀 Starting PTY reader task for PID {}...", child_pid);
                                            let tx_clone = tx.clone();
                                            let debug_raw_log_clone = debug_raw_log.clone();
                                            let log_file_clone = log_file.clone();
                                            let pty_async_clone = pty_async.clone();
                                            tokio::spawn(pty_reader_task(
                                                pty_async_fd,
                                                tx_clone,
                                                debug_raw_log_clone,
                                                log_file_clone,
                                                pty_async_clone,
                                            ));
                                            tracing::info!("✅ PTY reader task started successfully");
                                        }
                                        Err(e) => {
                                            tracing::error!("❌ FAILED to create PTY: {}", e);
                                            continue;
                                        }
                                    }
                                } else {
                                    tracing::info!("ℹ️  PTY was created by another client, using existing PTY");
                                }
                            } else {
                                tracing::info!("⏳ PTY creation in progress by another client, will use existing PTY");
                            }
                        } else {
                            tracing::info!("♻️  Using existing PTY for new client");
                        }

                        // Get current PTY for this client
                        let pty_async_clone = {
                            let pty_guard = pty_async.lock().await;
                            let pty_ref = pty_guard.clone();
                            tracing::debug!("📋 Retrieved PTY for client: has_pty={}", pty_ref.is_some());
                            pty_ref
                        };

                        let input_log_clone = input_log.clone();
                        let log_path_clone = log_path.clone();
                        let mut rx = tx.subscribe();
                        tracing::debug!("📺 Created broadcast receiver for client");

                        tracing::info!("🎬 Spawning client handler task...");
                        tokio::spawn(async move {
                            tracing::debug!("👤 Client handler task started");
                            match handle_client(stream, pty_async_clone, input_log_clone, &mut rx, &log_path_clone).await {
                                Err(e) => {
                                    tracing::warn!("❌ Client disconnected with error: {}", e);
                                }
                                Ok(_) => {
                                    tracing::info!("✅ Client disconnected gracefully");
                                }
                            }
                            tracing::debug!("👤 Client handler task ended");
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept client connection: {}", e);
                    }
                }
            }

            // Small delay to prevent busy looping
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                // Continue the loop to check signals
            }
        }
    }
}

// This function manages a single client's lifecycle.
async fn handle_client(
    stream: UnixStream,
    pty_async: Option<Arc<AsyncFd<std::os::unix::io::OwnedFd>>>,
    input_log: Option<Arc<Mutex<TokioFile>>>,
    rx: &mut broadcast::Receiver<PtyOutput>,
    log_path: &Path,
) -> Result<()> {
    let pty_info = if let Some(ref pty) = pty_async {
        format!("fd {}", pty.as_raw_fd())
    } else {
        "None".to_string()
    };
    tracing::info!("🎭 Client handler starting with PTY: {}", pty_info);

    let (mut client_reader, mut client_writer) = tokio::io::split(stream);

    // Initialize input parser for this client
    let mut input_parser = InputParser::new();

    // Replay history
    tracing::debug!(
        "📜 Attempting to replay history from {}",
        log_path.display()
    );
    match TokioFile::open(log_path).await {
        Ok(mut history_file) => {
            let bytes_copied = tokio::io::copy(&mut history_file, &mut client_writer).await?;
            tracing::info!("📜 Replayed {} bytes of history to client", bytes_copied);
        }
        Err(e) => {
            tracing::debug!("📜 No history file found ({}), starting fresh", e);
        }
    }

    tracing::debug!("🔄 Starting client event loop...");
    let mut loop_count = 0;
    loop {
        loop_count += 1;
        let mut client_buf = [0u8; 1024];
        tracing::debug!("🔄 Client event loop iteration {}", loop_count);

        tokio::select! {
            // Read from client (stdin) and write to PTY
            result = client_reader.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        tracing::info!("🔌 Client disconnected (EOF)");
                        break;
                    }
                    Ok(n) => {
                        tracing::debug!("⌨️  Client sent {} bytes: {:?}", n, String::from_utf8_lossy(&client_buf[..n]));
                        let input_data = &client_buf[..n];

                        // Process input through state machine to detect resize sequences
                        let (data_to_forward, resize_data) = input_parser.process_bytes(input_data);

                        // Handle resize if detected
                        if let Some(resize) = resize_data {
                            tracing::info!("Detected window resize: {}x{}", resize.rows, resize.cols);

                            // Apply new window size to PTY (if PTY exists)
                            if let Some(pty) = &pty_async {
                                if let Err(e) = apply_window_size_to_pty(pty.get_ref().as_raw_fd(), resize.rows, resize.cols) {
                                    tracing::warn!("Failed to apply window size to PTY: {}", e);
                                }
                            }
                        }

                        // Only forward and log non-resize data
                        if !data_to_forward.is_empty() {
                            // Log input data (client-to-PTY) - excluding resize sequences
                            if let Some(input_log) = &input_log {
                                let mut log = input_log.lock().await;
                                if let Err(e) = log.write_all(&data_to_forward).await {
                                    tracing::error!("Failed to write to input log: {}", e);
                                }
                            }

                            // Forward processed data to PTY (if PTY exists)
                            if let Some(pty) = &pty_async {
                                let mut guard = pty.writable().await.unwrap();
                                match guard.try_io(|inner| {
                                    let fd = inner.as_raw_fd();
                                    unsafe {
                                        let result = libc::write(fd, data_to_forward.as_ptr() as *const libc::c_void, data_to_forward.len());
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
                                    Ok(Ok(_)) => {}, // Write successful
                                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        // Retry later
                                        continue;
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!("Write error: {}", e);
                                        break;
                                    }
                                    Err(_) => {
                                        // Not ready, retry
                                        continue;
                                    }
                                }
                            } else {
                                tracing::warn!("Client tried to send input but no PTY exists");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading from client: {}", e);
                        break;
                    }
                }
            },

            // Read from broadcast channel (PTY output) and write to client
            result = rx.recv() => {
                match result {
                    Ok(PtyOutput::Data(data)) => {
                        tracing::debug!("📺 Received {} bytes from broadcast: {:?}", data.len(), String::from_utf8_lossy(&data));
                        client_writer.write_all(&data).await?;
                        tracing::debug!("📤 Forwarded {} bytes to client", data.len());
                    }
                    Ok(PtyOutput::Shutdown) => {
                        tracing::info!("🛑 Received shutdown signal. Closing client connection.");
                        let _ = client_writer.write_all(b"\r\n[Session terminated by server]\r\n").await;
                        break;
                    }
                    Err(e) => {
                        tracing::error!("❌ Broadcast channel error: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

// CLIENT LOGIC
async fn client_main(detach_char: u8, session_name: &str) -> Result<()> {
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
            server_main(&session_name, &cmd).await
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
            client_main(detach_byte, &session_name).await
        }
    };

    result
}
