use anyhow::Result;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::{File as TokioFile, OpenOptions};
use tokio::io::{unix::AsyncFd, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tracing;

use term_core::{
    apply_window_size_to_pty, create_new_pty_with_command, SignalManager, WindowSizeManager,
};
use term_protocol::constants::{DEBUG_RAW_LOGGING, INPUT_LOGGING};
use term_session::{
    get_debug_raw_log_path, get_input_log_path, get_log_path, get_socket_path, pty_reader_task,
    InputParser, PtyOutput,
};

/// Server implementation for term-replay
pub async fn run_server(session_name: &str, command: &[String]) -> Result<()> {
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
    spawn_zombie_reaper().await;

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

                        // Handle PTY creation if needed
                        handle_pty_creation(
                            &pty_async,
                            &pty_creating,
                            command,
                            &window_manager,
                            &tx,
                            &debug_raw_log,
                            &log_file,
                        ).await?;

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

async fn spawn_zombie_reaper() {
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
}

async fn handle_pty_creation(
    pty_async: &Arc<Mutex<Option<Arc<AsyncFd<std::os::unix::io::OwnedFd>>>>>,
    pty_creating: &Arc<tokio::sync::Semaphore>,
    command: &[String],
    window_manager: &WindowSizeManager,
    tx: &broadcast::Sender<PtyOutput>,
    debug_raw_log: &Option<Arc<Mutex<TokioFile>>>,
    log_file: &Arc<Mutex<TokioFile>>,
) -> Result<()> {
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
                tracing::info!(
                    "✅ Confirmed PTY creation needed, creating new PTY with command: {}",
                    command.join(" ")
                );

                // Create new PTY with custom command
                match create_new_pty_with_command(command) {
                    Ok((pty_master, child_pid)) => {
                        let pty_master_fd = pty_master.as_raw_fd();
                        tracing::info!(
                            "🎯 SUCCESS: Created PTY with command, PID: {}, FD: {}",
                            child_pid,
                            pty_master_fd
                        );

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
                        tracing::debug!(
                            "🔄 Creating AsyncFd wrapper for PTY fd {}...",
                            pty_master_fd
                        );
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
                        return Err(e);
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

    Ok(())
}

/// Handle a single client's lifecycle
pub async fn handle_client(
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
