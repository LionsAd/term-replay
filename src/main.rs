// src/main.rs

mod signals;
mod stdin;
mod terminal;
mod winsize;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{File as TokioFile, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, unix::AsyncFd};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast};

use signals::SignalManager;
use stdin::StdinReader;
use terminal::TerminalState;
use winsize::{WindowSizeManager, get_terminal_size};

/// Data sent from the PTY task to client handlers.
#[derive(Debug, Clone)]
enum PtyOutput {
    Data(Vec<u8>),
    Shutdown,
}

/// Parse detach character from string (e.g., "^\" -> Ctrl-\, "^?" -> DEL)
fn parse_detach_char(detach_str: &str) -> Result<u8> {
    if detach_str.starts_with('^') && detach_str.len() == 2 {
        let ch = detach_str.chars().nth(1).unwrap();
        if ch == '?' {
            Ok(0x7F) // DEL
        } else {
            Ok((ch as u8) & 0x1F) // Control character
        }
    } else if detach_str.len() == 1 {
        Ok(detach_str.chars().next().unwrap() as u8)
    } else {
        anyhow::bail!(
            "Invalid detach character: '{}'. Use '^X' for control characters or '^?' for DEL",
            detach_str
        );
    }
}

/// Window resize data
#[derive(Debug, PartialEq)]
struct WindowResizeData {
    rows: u16,
    cols: u16,
}

/// State machine for parsing input and detecting resize sequences
#[derive(Debug, Clone, Copy, PartialEq)]
enum InputParseState {
    Normal,
    Escape,        // Saw ESC (\x1b)
    Csi,           // Saw ESC [
    Csi8,          // Saw ESC [ 8
    Csi8Semicolon, // Saw ESC [ 8 ;
    Rows,          // Parsing row digits
    RowsSemicolon, // Saw semicolon after rows
    Cols,          // Parsing column digits
}

/// Input parser for detecting resize sequences
struct InputParser {
    state: InputParseState,
    sequence_buffer: Vec<u8>,
    rows_str: String,
    cols_str: String,
}

impl InputParser {
    fn new() -> Self {
        Self {
            state: InputParseState::Normal,
            sequence_buffer: Vec::new(),
            rows_str: String::new(),
            cols_str: String::new(),
        }
    }

    /// Process input bytes and extract any complete resize sequences
    /// Returns (data_to_forward, optional_resize_data)
    fn process_bytes(&mut self, input: &[u8]) -> (Vec<u8>, Option<WindowResizeData>) {
        let mut output = Vec::new();
        let mut resize_data = None;

        for &byte in input {
            match self.process_byte(byte) {
                InputAction::Forward(b) => output.push(b),
                InputAction::ForwardSequence => {
                    // Invalid sequence, forward the accumulated buffer
                    output.extend_from_slice(&self.sequence_buffer);
                    self.reset();
                }
                InputAction::ResizeDetected(data) => {
                    // Take the first resize sequence found
                    if resize_data.is_none() {
                        resize_data = Some(data);
                    }
                    self.reset();
                }
                InputAction::Continue => {
                    // Continue accumulating sequence
                }
            }
        }

        (output, resize_data)
    }

    fn process_byte(&mut self, byte: u8) -> InputAction {
        match (self.state, byte) {
            // Normal state: scan for ESC
            (InputParseState::Normal, 0x1b) => {
                self.state = InputParseState::Escape;
                self.sequence_buffer.clear();
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Normal, b) => InputAction::Forward(b),

            // Escape state: look for [
            (InputParseState::Escape, b'[') => {
                self.state = InputParseState::Csi;
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Escape, _) => {
                // Not a CSI sequence, forward ESC and current byte
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // CSI state: look for 8
            (InputParseState::Csi, b'8') => {
                self.state = InputParseState::Csi8;
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Csi, _) => {
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // CSI8 state: look for ;
            (InputParseState::Csi8, b';') => {
                self.state = InputParseState::Csi8Semicolon;
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Csi8, _) => {
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // CSI8; state: start collecting row digits
            (InputParseState::Csi8Semicolon, b'0'..=b'9') => {
                self.state = InputParseState::Rows;
                self.rows_str.clear();
                self.rows_str.push(byte as char);
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Csi8Semicolon, _) => {
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // Rows state: collect more digits or semicolon
            (InputParseState::Rows, b'0'..=b'9') => {
                self.rows_str.push(byte as char);
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Rows, b';') => {
                self.state = InputParseState::RowsSemicolon;
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Rows, _) => {
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // Rows; state: start collecting column digits
            (InputParseState::RowsSemicolon, b'0'..=b'9') => {
                self.state = InputParseState::Cols;
                self.cols_str.clear();
                self.cols_str.push(byte as char);
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::RowsSemicolon, _) => {
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }

            // Cols state: collect more digits or 't'
            (InputParseState::Cols, b'0'..=b'9') => {
                self.cols_str.push(byte as char);
                self.sequence_buffer.push(byte);
                InputAction::Continue
            }
            (InputParseState::Cols, b't') => {
                // Complete sequence! Parse the dimensions
                if let (Ok(rows), Ok(cols)) =
                    (self.rows_str.parse::<u16>(), self.cols_str.parse::<u16>())
                {
                    if rows > 0 && cols > 0 {
                        return InputAction::ResizeDetected(WindowResizeData { rows, cols });
                    }
                }
                // Invalid dimensions, forward the sequence including 't'
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }
            (InputParseState::Cols, _) => {
                // Invalid ending, forward sequence including this byte
                self.sequence_buffer.push(byte);
                InputAction::ForwardSequence
            }
        }
    }

    fn reset(&mut self) {
        self.state = InputParseState::Normal;
        self.sequence_buffer.clear();
        self.rows_str.clear();
        self.cols_str.clear();
    }
}

/// Actions to take when processing input bytes
enum InputAction {
    Forward(u8),                      // Forward this byte normally
    ForwardSequence,                  // Forward accumulated sequence buffer
    ResizeDetected(WindowResizeData), // Complete resize sequence detected
    Continue,                         // Continue accumulating sequence
}

/// Apply window size to PTY file descriptor
fn apply_window_size_to_pty(pty_fd: RawFd, rows: u16, cols: u16) -> Result<()> {
    use nix::libc::winsize;

    let ws = winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let result = unsafe { nix::libc::ioctl(pty_fd, nix::libc::TIOCSWINSZ, &ws) };

    if result < 0 {
        anyhow::bail!(
            "Failed to set window size: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

/// Create a new PTY with bash process - returns (pty_master, child_pid)
fn create_new_pty_with_command(
    command: &[String],
) -> Result<(std::os::unix::io::OwnedFd, nix::unistd::Pid)> {
    // Validate command
    if command.is_empty() {
        anyhow::bail!("Command cannot be empty");
    }

    // Join command parts into a single string for bash -c
    let cmd_string = command.join(" ");
    tracing::info!("Creating PTY with command: {}", cmd_string);

    // Create a completely new PTY
    let pty_master = match unsafe { forkpty(None, None)? } {
        ForkptyResult::Parent { master, child } => {
            tracing::info!(
                "Created new PTY. Master fd: {}, Child pid: {}",
                master.as_raw_fd(),
                child
            );
            (master, child)
        }
        ForkptyResult::Child => {
            // In child process, execute bash -c "command"
            let bash_path = CString::new("/bin/bash")?;
            let bash_name = CString::new("bash")?;
            let c_flag = CString::new("-c")?;
            let command_cstr = CString::new(cmd_string)?;

            let args = [
                bash_name.as_c_str(),
                c_flag.as_c_str(),
                command_cstr.as_c_str(),
            ];

            unistd::execvp(&bash_path, &args)?;
            unreachable!();
        }
    };

    Ok(pty_master)
}

/// PTY reader task that handles PTY output and manages PTY lifecycle
async fn pty_reader_task(
    pty_async_fd: Arc<AsyncFd<std::os::unix::io::OwnedFd>>,
    tx: broadcast::Sender<PtyOutput>,
    debug_raw_log: Option<Arc<Mutex<TokioFile>>>,
    log_file: Arc<Mutex<TokioFile>>,
    pty_async_shared: Arc<Mutex<Option<Arc<AsyncFd<std::os::unix::io::OwnedFd>>>>>,
) {
    let pty_fd = pty_async_fd.as_raw_fd();
    tracing::info!("📖 PTY reader task started for fd {}", pty_fd);

    let mut buf = [0u8; 1024];
    let mut parser = EscapeParser::new();
    let mut terminal_mode = TerminalMode::Normal;
    let mut read_count = 0;

    loop {
        tracing::debug!(
            "🔄 PTY reader loop iteration {}, waiting for readable...",
            read_count
        );
        let mut guard = pty_async_fd.readable().await.unwrap();
        match guard.try_io(|inner| {
            let fd = inner.as_raw_fd();
            unsafe {
                let result = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
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
                tracing::warn!(
                    "🔚 PTY fd {} EOF after {} reads. Shell process exited!",
                    pty_fd,
                    read_count
                );
                tracing::info!("💡 This indicates bash exited (normal or abnormal)");

                // Clear the shared PTY reference - back to "no PTY" state
                {
                    tracing::debug!("🧹 Clearing PTY from shared state...");
                    let mut pty_guard = pty_async_shared.lock().await;
                    *pty_guard = None;
                    tracing::debug!("✅ PTY cleared from shared state");
                }

                // Write an exit message to the main log
                let exit_message = format!(
                    "\r\n[{}] Shell process exited. Session can be reconnected.\r\n",
                    chrono::Utc::now().format("%H:%M:%S")
                );

                // Write to session log
                {
                    let mut log = log_file.lock().await;
                    if let Err(e) = log.write_all(exit_message.as_bytes()).await {
                        tracing::error!("Failed to write exit message to log: {}", e);
                    }
                }

                // Broadcast exit message to all clients
                let _ = tx.send(PtyOutput::Data(exit_message.as_bytes().to_vec()));

                // Send shutdown signal to all clients
                if let Err(e) = tx.send(PtyOutput::Shutdown) {
                    tracing::error!("Failed to send shutdown signal: {}", e);
                }

                tracing::info!("🏁 PTY reader task exiting - server ready for new connections");
                break;
            }
            Ok(Ok(n)) => {
                read_count += 1;
                let data = buf[..n].to_vec();
                tracing::debug!(
                    "📥 Read {} bytes from PTY fd {} (read #{}): {:?}",
                    n,
                    pty_fd,
                    read_count,
                    String::from_utf8_lossy(&data)
                );

                // Raw debug logging - write ALL data unconditionally
                if let Some(debug_log) = &debug_raw_log {
                    let mut debug = debug_log.lock().await;
                    if let Err(e) = debug.write_all(&data).await {
                        tracing::error!("Failed to write to debug raw log: {}", e);
                    }
                }

                // Always broadcast to all clients (they see everything live)
                if tx.send(PtyOutput::Data(data.clone())).is_err() {
                    // This means no clients are connected, which is fine.
                }

                // Parse escape sequences and create filtered data for main log
                let actions = parser.parse(&data);

                for action in &actions {
                    match action {
                        SequenceAction::EnterAlternateScreen => {
                            tracing::debug!("Entering alternate screen mode");
                            terminal_mode = TerminalMode::Alternate;
                        }
                        SequenceAction::ExitAlternateScreen => {
                            tracing::debug!("Exiting alternate screen mode");
                            terminal_mode = TerminalMode::Normal;
                        }
                        SequenceAction::DestructiveClear => {
                            tracing::debug!("Destructive clear detected");

                            // Truncate the log file
                            {
                                let mut log = log_file.lock().await;
                                if let Err(e) = log.set_len(0).await {
                                    tracing::error!("Failed to truncate log file: {}", e);
                                }
                                if let Err(e) = log.seek(std::io::SeekFrom::Start(0)).await {
                                    tracing::error!("Failed to seek to start of log: {}", e);
                                }
                            }
                        }
                    }
                }

                // Write to filtered log only in Normal mode and only if no special sequences
                if terminal_mode == TerminalMode::Normal && actions.is_empty() {
                    let mut log = log_file.lock().await;
                    if let Err(e) = log.write_all(&data).await {
                        tracing::error!("Failed to write to log: {}", e);
                    }
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Not ready yet, continue the loop
                continue;
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to read from PTY master: {}", e);
                break;
            }
            Err(_) => {
                // Not ready yet, continue the loop
                continue;
            }
        }
    }
}

// Debug flag - set to true to enable raw logging
const DEBUG_RAW_LOGGING: bool = true;
const INPUT_LOGGING: bool = true;

/// Get the directory for terminal replay files, checking TERM_REPLAY_DIR env var
fn get_term_replay_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TERM_REPLAY_DIR") {
        PathBuf::from(dir)
    } else {
        PathBuf::from("/tmp")
    }
}

/// Internal function that generates socket path in specified directory
fn get_socket_path_in_dir(socket_name: &str, base_dir: &Path) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    path.push(format!("{}.sock", socket_name));
    path
}

/// Generate socket path for a given session name
fn get_socket_path(socket_name: &str) -> PathBuf {
    let base_dir = get_term_replay_dir();
    get_socket_path_in_dir(socket_name, &base_dir)
}

/// Internal function that generates log path in specified directory
fn get_log_path_in_dir(socket_name: &str, base_dir: &Path) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    path.push(format!("{}.log", socket_name));
    path
}

/// Generate main log path for a given session name
fn get_log_path(socket_name: &str) -> PathBuf {
    let base_dir = get_term_replay_dir();
    get_log_path_in_dir(socket_name, &base_dir)
}

/// Internal function that generates debug raw log path in specified directory
fn get_debug_raw_log_path_in_dir(socket_name: &str, base_dir: &Path) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    path.push(format!("{}-raw.log", socket_name));
    path
}

/// Generate debug raw log path for a given session name
fn get_debug_raw_log_path(socket_name: &str) -> PathBuf {
    let base_dir = get_term_replay_dir();
    get_debug_raw_log_path_in_dir(socket_name, &base_dir)
}

/// Internal function that generates input log path in specified directory
fn get_input_log_path_in_dir(socket_name: &str, base_dir: &Path) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    path.push(format!("{}-input.log", socket_name));
    path
}

/// Generate input log path for a given session name
fn get_input_log_path(socket_name: &str) -> PathBuf {
    let base_dir = get_term_replay_dir();
    get_input_log_path_in_dir(socket_name, &base_dir)
}

/// Validate session name using allowlist pattern to prevent directory traversal and other attacks
fn validate_session_name(session_name: &str) -> Result<()> {
    // Check basic constraints first for better error messages
    if session_name.is_empty() {
        anyhow::bail!("Session name cannot be empty");
    }

    if session_name.len() > 100 {
        anyhow::bail!(
            "Session name too long (max 100 chars, got {}): '{}'",
            session_name.len(),
            session_name
        );
    }

    // Use allowlist approach: only allow alphanumeric, hyphens, underscores, and dots (not at start)
    // This prevents directory traversal, Unicode issues, and control characters
    let is_valid_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';

    if !session_name.chars().all(is_valid_char) {
        let mut invalid_chars: Vec<char> = session_name
            .chars()
            .filter(|c| !is_valid_char(*c))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        // Sort for deterministic error messages
        invalid_chars.sort();
        let invalid_chars_str: String = invalid_chars.into_iter().collect();
        anyhow::bail!(
            "Session name contains invalid characters: '{}'. Only alphanumeric, '-', '_', and '.' are allowed: '{}'",
            invalid_chars_str,
            session_name
        );
    }

    // Don't allow starting with dot (hidden files) or hyphen (command-line confusion)
    if session_name.starts_with('.') {
        anyhow::bail!("Session name cannot start with '.': '{}'", session_name);
    }

    if session_name.starts_with('-') {
        anyhow::bail!("Session name cannot start with '-': '{}'", session_name);
    }

    // Prevent directory traversal patterns
    if session_name.contains("..") {
        anyhow::bail!("Session name cannot contain '..': '{}'", session_name);
    }

    Ok(())
}

/// Internal function that generates PID file path in specified directory
fn get_pid_file_path_in_dir(socket_name: &str, base_dir: &Path) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    path.push(format!("{}.pid", socket_name));
    path
}

/// Generate PID file path for a given session name
fn get_pid_file_path(socket_name: &str) -> PathBuf {
    let base_dir = get_term_replay_dir();
    get_pid_file_path_in_dir(socket_name, &base_dir)
}

/// Session state for smart takeover logic
#[derive(Debug, PartialEq)]
enum SessionState {
    Available,          // No existing session
    ActiveSession(u32), // Running server with PID
    StaleSession(u32),  // Dead process, socket/PID exist
    OrphanSocket,       // Socket exists, no PID file
}

/// Unix-only process existence check using kill(pid, 0)
/// Returns true if process exists (even if we don't have permission to signal it)
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) => true, // Process exists and we have permission to signal it
        Err(nix::errno::Errno::EPERM) => true, // Process exists but we don't have permission - still running
        Err(nix::errno::Errno::ESRCH) => false, // No such process
        Err(e) => {
            tracing::warn!("Unexpected error checking process {}: {}", pid, e);
            false // Assume not running on other errors
        }
    }
}

/// Read PID from PID file, returning None if file doesn't exist or contains invalid data
fn read_pid_file(pid_file_path: &Path) -> Option<u32> {
    match std::fs::read_to_string(pid_file_path) {
        Ok(contents) => match contents.trim().parse::<u32>() {
            Ok(pid) => Some(pid),
            Err(_) => {
                tracing::warn!(
                    "PID file {} contains invalid data: {:?}",
                    pid_file_path.display(),
                    contents
                );
                None
            }
        },
        Err(_) => None, // File doesn't exist or can't be read
    }
}

/// Check the current state of a session (socket + PID file)
fn check_session_state(socket_path: &Path, pid_file_path: &Path) -> SessionState {
    if !socket_path.exists() {
        return SessionState::Available;
    }

    // Socket exists, check PID file
    let pid = match read_pid_file(pid_file_path) {
        Some(pid) => pid,
        None => return SessionState::OrphanSocket,
    };

    // Test if process is actually running
    if is_process_running(pid) {
        SessionState::ActiveSession(pid)
    } else {
        SessionState::StaleSession(pid)
    }
}

/// Clean up stale session files (socket and PID file)
fn cleanup_stale_session(socket_path: &Path, pid_file_path: &Path) -> Result<()> {
    // Remove stale socket - ignore NotFound errors (file may already be gone)
    if let Err(e) = std::fs::remove_file(socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).with_context(|| {
                format!("Failed to remove stale socket: {}", socket_path.display())
            });
        }
    }

    // Remove stale PID file - ignore NotFound errors (file may already be gone)
    if let Err(e) = std::fs::remove_file(pid_file_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).with_context(|| {
                format!(
                    "Failed to remove stale PID file: {}",
                    pid_file_path.display()
                )
            });
        }
    }

    Ok(())
}

/// RAII guard to ensure socket cleanup on drop
struct SocketGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    /// Disable cleanup (call when server shuts down normally)
    fn disarm(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.should_cleanup {
            tracing::debug!("Cleaning up socket on drop: {}", self.path.display());
            if let Err(e) = std::fs::remove_file(&self.path) {
                // Ignore NotFound errors - file may have been cleaned up already
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to cleanup socket on drop: {}", e);
                }
            }
        }
    }
}

/// RAII guard to ensure PID file cleanup on drop
struct PidFileGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl PidFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    /// Disable cleanup (call when server shuts down normally)
    fn disarm(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if self.should_cleanup {
            tracing::debug!("Cleaning up PID file on drop: {}", self.path.display());
            if let Err(e) = std::fs::remove_file(&self.path) {
                // Ignore NotFound errors - file may have been cleaned up already
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to cleanup PID file on drop: {}", e);
                }
            }
        }
    }
}

/// Create PID file securely with proper permissions, ensuring parent directory exists
/// Uses atomic write (temp file + rename) to prevent partial reads
fn create_pid_file(pid_file_path: &Path, pid: u32) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    // Ensure parent directory exists
    if let Some(parent_dir) = pid_file_path.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).with_context(|| {
                format!(
                    "Failed to create parent directory for PID file: {}",
                    parent_dir.display()
                )
            })?;
            tracing::debug!(
                "Created parent directory for PID file: {}",
                parent_dir.display()
            );
        }
    }

    // Create temporary file in same directory for atomic rename
    let temp_path = pid_file_path.with_extension("pid.tmp");

    use std::os::unix::fs::OpenOptionsExt;
    let mut temp_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600) // Owner read/write only
        .open(&temp_path)
        .with_context(|| {
            format!(
                "Failed to create temporary PID file: {}",
                temp_path.display()
            )
        })?;

    // Write PID to temp file
    temp_file
        .write_all(pid.to_string().as_bytes())
        .with_context(|| {
            format!(
                "Failed to write to temporary PID file: {}",
                temp_path.display()
            )
        })?;
    temp_file
        .sync_all()
        .with_context(|| format!("Failed to sync temporary PID file: {}", temp_path.display()))?;

    // Close temp file before rename (required on some systems)
    drop(temp_file);

    // Atomically replace target file with temp file
    fs::rename(&temp_path, pid_file_path).with_context(|| {
        format!(
            "Failed to rename temporary PID file {} to {}",
            temp_path.display(),
            pid_file_path.display()
        )
    })?;

    tracing::info!(
        "Created PID file: {} (PID: {})",
        pid_file_path.display(),
        pid
    );
    Ok(())
}

// Terminal mode tracking
#[derive(Debug, Clone, Copy, PartialEq)]
enum TerminalMode {
    Normal,    // Log everything
    Alternate, // Skip logging (vim, less, etc.)
}

// Escape sequence parser state
#[derive(Debug, Clone, Copy, PartialEq)]
enum ParseState {
    Normal,
    Escape,      // Saw ESC (\x1b)
    Csi,         // Saw ESC [
    CsiQuestion, // Saw ESC [ ?
    Csi1,        // Saw ESC [ ? 1
    Csi10,       // Saw ESC [ ? 1 0
    Csi104,      // Saw ESC [ ? 1 0 4
    Csi1049,     // Saw ESC [ ? 1 0 4 9
    Csi3,        // Saw ESC [ 3
}

// Actions to take based on detected sequences
#[derive(Debug, Clone, PartialEq)]
enum SequenceAction {
    EnterAlternateScreen,
    ExitAlternateScreen,
    DestructiveClear,
}

// Escape sequence parser
struct EscapeParser {
    state: ParseState,
    buffer: Vec<u8>,
}

impl EscapeParser {
    fn new() -> Self {
        Self {
            state: ParseState::Normal,
            buffer: Vec::new(),
        }
    }

    fn parse(&mut self, data: &[u8]) -> Vec<SequenceAction> {
        let mut actions = Vec::new();

        for &byte in data {
            self.buffer.push(byte);

            match (self.state, byte) {
                // Normal state: scan for ESC
                (ParseState::Normal, 0x1b) => {
                    self.state = ParseState::Escape;
                }
                (ParseState::Normal, _) => {
                    // Continue in normal mode
                }

                // Escape state: look for [
                (ParseState::Escape, b'[') => {
                    self.state = ParseState::Csi;
                }
                (ParseState::Escape, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI state: look for ? or 3
                (ParseState::Csi, b'?') => {
                    self.state = ParseState::CsiQuestion;
                }
                (ParseState::Csi, b'3') => {
                    self.state = ParseState::Csi3;
                }
                (ParseState::Csi, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI? state: look for 1
                (ParseState::CsiQuestion, b'1') => {
                    self.state = ParseState::Csi1;
                }
                (ParseState::CsiQuestion, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI?1 state: look for 0
                (ParseState::Csi1, b'0') => {
                    self.state = ParseState::Csi10;
                }
                (ParseState::Csi1, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI?10 state: look for 4
                (ParseState::Csi10, b'4') => {
                    self.state = ParseState::Csi104;
                }
                (ParseState::Csi10, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI?104 state: look for 9
                (ParseState::Csi104, b'9') => {
                    self.state = ParseState::Csi1049;
                }
                (ParseState::Csi104, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI?1049 state: look for h or l
                (ParseState::Csi1049, b'h') => {
                    actions.push(SequenceAction::EnterAlternateScreen);
                    self.state = ParseState::Normal;
                }
                (ParseState::Csi1049, b'l') => {
                    actions.push(SequenceAction::ExitAlternateScreen);
                    self.state = ParseState::Normal;
                }
                (ParseState::Csi1049, _) => {
                    self.state = ParseState::Normal;
                }

                // CSI3 state: look for J
                (ParseState::Csi3, b'J') => {
                    actions.push(SequenceAction::DestructiveClear);
                    self.state = ParseState::Normal;
                }
                (ParseState::Csi3, _) => {
                    self.state = ParseState::Normal;
                }
            }

            // Reset to normal state on ESC if not in Normal/Escape
            if byte == 0x1b && !matches!(self.state, ParseState::Normal | ParseState::Escape) {
                self.state = ParseState::Escape;
            }
        }

        actions
    }

    #[allow(dead_code)]
    fn reset(&mut self) {
        self.state = ParseState::Normal;
        self.buffer.clear();
    }
}

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
    // Validate session name to prevent directory traversal attacks
    validate_session_name(session_name)?;

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
    let pid_file_path = get_pid_file_path(session_name);

    // Check session state and handle takeover logic
    match check_session_state(&socket_path, &pid_file_path) {
        SessionState::Available => {
            // Normal startup - no existing session
        }
        SessionState::ActiveSession(pid) => {
            anyhow::bail!(
                "Session '{}' is active (PID: {}, socket: {}). Use a different session name or stop the existing server.",
                session_name,
                pid,
                socket_path.display()
            );
        }
        SessionState::StaleSession(pid) => {
            tracing::warn!(
                "Taking over stale session '{}' (dead PID: {}, socket: {}). Previous session logs preserved.",
                session_name,
                pid,
                socket_path.display()
            );
            cleanup_stale_session(&socket_path, &pid_file_path)?;
        }
        SessionState::OrphanSocket => {
            tracing::warn!(
                "Taking over orphaned session '{}' (socket: {}, no PID file). Previous session logs preserved.",
                session_name,
                socket_path.display()
            );
            cleanup_stale_session(&socket_path, &pid_file_path)?;
        }
    }

    // Clean up debug and input logs from previous runs (preserve main log)
    if DEBUG_RAW_LOGGING {
        if let Err(e) = std::fs::remove_file(&debug_raw_log_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e).with_context(|| {
                    format!(
                        "Failed to remove debug log: {}",
                        debug_raw_log_path.display()
                    )
                });
            }
        }
    }
    if INPUT_LOGGING {
        if let Err(e) = std::fs::remove_file(&input_log_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e).with_context(|| {
                    format!("Failed to remove input log: {}", input_log_path.display())
                });
            }
        }
    }

    // 1. No PTY creation at startup - will be created on first client connection

    // Spawn a dedicated task to reap zombie child processes
    tokio::spawn(async move {
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
        use tokio::signal::unix::{SignalKind, signal};

        // The OS sends SIGCHLD when a child process (like our PTY) exits
        let mut sigchld_stream =
            signal(SignalKind::child()).expect("Failed to create SIGCHLD listener");

        tracing::debug!("🧟 Zombie reaper task started - listening for SIGCHLD");

        // Loop forever, waiting for the signal
        while sigchld_stream.recv().await.is_some() {
            tracing::debug!("📢 Received SIGCHLD - reaping zombie children");

            // Loop to reap ALL zombie children that might exist
            // Using WNOHANG means waitpid will return immediately
            // if there are no more zombies to reap
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
                        // No more zombies to reap right now
                        tracing::debug!("✅ No more zombie children to reap");
                        break;
                    }
                    Err(nix::errno::Errno::ECHILD) => {
                        // No children left to wait for
                        tracing::debug!("ℹ️  No child processes exist");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("❌ Error in waitpid: {}", e);
                        break;
                    }
                    _ => {
                        // Other wait statuses we don't need to handle for zombies
                        tracing::debug!("🔄 Other wait status encountered, continuing");
                    }
                }
            }
        }
        tracing::debug!("🧟 Zombie reaper task exiting");
    });

    // Bind the socket first - this is the critical section that must succeed
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind to socket: {}", socket_path.display()))?;

    // Create RAII guard to ensure socket cleanup on any error after binding
    let mut _socket_guard = SocketGuard::new(socket_path.clone());

    // Only create PID file after successful socket binding to avoid orphaned PID files
    let current_pid = std::process::id();
    create_pid_file(&pid_file_path, current_pid)
        .with_context(|| "Failed to create PID file after successful socket binding")?;

    // Create RAII guard to ensure PID file cleanup on errors
    let mut _pid_guard = PidFileGuard::new(pid_file_path.clone());
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

    // 3. PTY Reader Task will be created on-demand when first client connects

    // 4. Main Accept Loop with Signal Handling
    // This loop waits for new clients to connect and handles window size changes.
    tracing::info!("Server listening on {}", socket_path.display());
    loop {
        // Server window size changes are handled per-client via escape sequences

        // Check for shutdown signal
        if signal_manager.check_shutdown_requested() {
            if let Some(sig) = signal_manager.get_shutdown_signal() {
                tracing::info!("Received shutdown signal: {:?}, terminating server", sig);
            }

            // Clean up socket and PID files before shutdown
            if let Err(e) = std::fs::remove_file(&socket_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        "Failed to remove socket file {}: {}",
                        socket_path.display(),
                        e
                    );
                }
            } else {
                tracing::debug!("Cleaned up socket file: {}", socket_path.display());
            }

            if let Err(e) = std::fs::remove_file(&pid_file_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        "Failed to remove PID file {}: {}",
                        pid_file_path.display(),
                        e
                    );
                }
            } else {
                tracing::debug!("Cleaned up PID file: {}", pid_file_path.display());
            }

            // Disarm the guards since we're cleaning up manually
            _socket_guard.disarm();
            _pid_guard.disarm();
            return Ok(());
        }

        tokio::select! {
            // Accept new client connections
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        tracing::info!("🔌 New client connected from {:?}", addr);

                        // Check if we need to create a PTY - use a more robust check
                        let needs_pty = {
                            let pty_guard = pty_async.lock().await;
                            let has_pty = pty_guard.is_some();
                            tracing::debug!("📊 PTY check: has_pty={}", has_pty);
                            pty_guard.is_none()
                        };

                        if needs_pty {
                            tracing::info!("🚀 No PTY exists, attempting to create new PTY with bash...");

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

                                            // Create async wrapper - PASS OWNED FD TO KEEP IT ALIVE
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

    // a. Replay history
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
            // b. Read from client (stdin) and write to PTY
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

            // c. Read from broadcast channel (PTY output) and write to client
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
    // Defaults to ERROR level for clean server operation while still showing critical issues
    // Set RUST_LOG environment variable to control logging level
    // Examples: RUST_LOG=info, RUST_LOG=debug, RUST_LOG=term_replay=debug
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    #[test]
    fn test_detach_char_parsing() {
        // Test control characters
        assert_eq!(parse_detach_char("^\\").unwrap(), 0x1C); // Ctrl-\
        assert_eq!(parse_detach_char("^C").unwrap(), 0x03); // Ctrl-C
        assert_eq!(parse_detach_char("^A").unwrap(), 0x01); // Ctrl-A

        // Test DEL
        assert_eq!(parse_detach_char("^?").unwrap(), 0x7F); // DEL

        // Test single character
        assert_eq!(parse_detach_char("x").unwrap(), b'x');

        // Test invalid formats
        assert!(parse_detach_char("^too_long").is_err());
        assert!(parse_detach_char("").is_err());
    }

    #[test]
    fn test_create_new_pty_with_bash() {
        // This test verifies that PTY creation works
        // Note: This spawns a real bash process, so we need to be careful
        let result = create_new_pty_with_bash();
        assert!(result.is_ok(), "Should be able to create PTY with bash");

        let (pty_master, child_pid) = result.unwrap();

        // Verify we got valid file descriptor and PID
        assert!(
            pty_master.as_raw_fd() > 0,
            "PTY master should have valid fd"
        );
        assert!(child_pid.as_raw() > 0, "Child PID should be positive");

        // Clean up - kill the child process
        let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
        let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
    }

    #[tokio::test]
    async fn test_pty_lifecycle() {
        // Test that PTY state management works correctly
        let (_tx, _) = broadcast::channel::<PtyOutput>(1024);
        let pty_async: Arc<Mutex<Option<Arc<AsyncFd<RawFd>>>>> = Arc::new(Mutex::new(None));

        // Initially no PTY should exist
        {
            let pty_guard = pty_async.lock().await;
            assert!(pty_guard.is_none(), "Initially no PTY should exist");
        }

        // Create a PTY
        let (pty_master, child_pid) = create_new_pty_with_bash().unwrap();
        let pty_master_fd = pty_master.as_raw_fd();

        // Make it non-blocking
        nix::fcntl::fcntl(
            pty_master_fd,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .unwrap();

        let pty_async_fd = Arc::new(AsyncFd::new(pty_master_fd).unwrap());

        // Store in shared state
        {
            let mut pty_guard = pty_async.lock().await;
            *pty_guard = Some(pty_async_fd.clone());
        }

        // Verify PTY exists
        {
            let pty_guard = pty_async.lock().await;
            assert!(pty_guard.is_some(), "PTY should exist after creation");
        }

        // Clean up
        let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
        let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));

        // Clear PTY state (simulating shell exit)
        {
            let mut pty_guard = pty_async.lock().await;
            *pty_guard = None;
        }

        // Verify PTY is cleared
        {
            let pty_guard = pty_async.lock().await;
            assert!(
                pty_guard.is_none(),
                "PTY should be cleared after shell exit"
            );
        }
    }

    #[test]
    fn test_pty_respawn_concept() {
        // Test the core concept: we can create multiple PTYs sequentially

        // Create first PTY
        let result1 = create_new_pty_with_bash();
        assert!(result1.is_ok(), "First PTY creation should succeed");
        let (pty1, child1) = result1.unwrap();
        let fd1 = pty1.as_raw_fd();

        // Kill the first child
        let _ = nix::sys::signal::kill(child1, nix::sys::signal::Signal::SIGTERM);
        let _ = nix::sys::wait::waitpid(child1, Some(nix::sys::wait::WaitPidFlag::WNOHANG));

        // Create second PTY (this simulates respawn)
        let result2 = create_new_pty_with_bash();
        assert!(result2.is_ok(), "Second PTY creation should succeed");
        let (pty2, child2) = result2.unwrap();
        let fd2 = pty2.as_raw_fd();

        // They should have different file descriptors
        assert_ne!(fd1, fd2, "New PTY should have different fd");

        // Clean up second child
        let _ = nix::sys::signal::kill(child2, nix::sys::signal::Signal::SIGTERM);
        let _ = nix::sys::wait::waitpid(child2, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
    }

    #[test]
    fn test_input_parser_complete_sequence() {
        let mut parser = InputParser::new();

        // Test complete resize sequence in one chunk
        let input = b"\x1b[8;24;80t";
        let (output, resize) = parser.process_bytes(input);

        assert!(output.is_empty()); // Resize sequence should not be forwarded
        assert_eq!(resize, Some(WindowResizeData { rows: 24, cols: 80 }));
    }

    #[test]
    fn test_input_parser_split_sequence() {
        let mut parser = InputParser::new();

        // Test sequence split across multiple chunks
        let (output1, resize1) = parser.process_bytes(b"\x1b[8;2");
        assert!(output1.is_empty());
        assert!(resize1.is_none());

        let (output2, resize2) = parser.process_bytes(b"4;80t");
        assert!(output2.is_empty());
        assert_eq!(resize2, Some(WindowResizeData { rows: 24, cols: 80 }));
    }

    #[test]
    fn test_input_parser_mixed_data() {
        let mut parser = InputParser::new();

        // Test resize sequence mixed with normal data
        let input = b"hello\x1b[8;30;120tworld";
        let (output, resize) = parser.process_bytes(input);

        assert_eq!(output, b"helloworld");
        assert_eq!(
            resize,
            Some(WindowResizeData {
                rows: 30,
                cols: 120
            })
        );
    }

    #[test]
    fn test_input_parser_invalid_sequences() {
        let mut parser = InputParser::new();

        // Test invalid sequence (wrong ending)
        let (output, resize) = parser.process_bytes(b"\x1b[8;24;80x");
        assert_eq!(output, b"\x1b[8;24;80x"); // Should forward invalid sequence
        assert!(resize.is_none());

        parser = InputParser::new();

        // Test invalid sequence (wrong CSI command)
        let (output, resize) = parser.process_bytes(b"\x1b[7;24;80t");
        assert_eq!(output, b"\x1b[7;24;80t"); // Should forward invalid sequence
        assert!(resize.is_none());

        parser = InputParser::new();

        // Test partial sequence interrupted by normal data
        let (output, resize) = parser.process_bytes(b"\x1b[8;hello");
        assert_eq!(output, b"\x1b[8;hello"); // Should forward when sequence becomes invalid
        assert!(resize.is_none());
    }

    #[test]
    fn test_input_parser_multiple_sequences() {
        let mut parser = InputParser::new();

        // Test multiple resize sequences
        let input = b"\x1b[8;24;80t\x1b[8;30;120t";
        let (output, resize) = parser.process_bytes(input);

        assert!(output.is_empty());
        // Should only detect the first complete sequence in a single call
        assert_eq!(resize, Some(WindowResizeData { rows: 24, cols: 80 }));
    }

    #[test]
    fn test_input_parser_edge_cases() {
        let mut parser = InputParser::new();

        // Test zero dimensions (invalid)
        let (output, resize) = parser.process_bytes(b"\x1b[8;0;80t");
        assert_eq!(output, b"\x1b[8;0;80t"); // Should forward invalid sequence
        assert!(resize.is_none());

        parser = InputParser::new();

        // Test very large dimensions
        let (output, resize) = parser.process_bytes(b"\x1b[8;999;999t");
        assert!(output.is_empty());
        assert_eq!(
            resize,
            Some(WindowResizeData {
                rows: 999,
                cols: 999
            })
        );

        parser = InputParser::new();

        // Test non-numeric dimensions
        let (output, resize) = parser.process_bytes(b"\x1b[8;abc;80t");
        assert_eq!(output, b"\x1b[8;abc;80t"); // Should forward invalid sequence
        assert!(resize.is_none());
    }

    #[test]
    fn test_input_parser_reset_after_detection() {
        let mut parser = InputParser::new();

        // Detect one sequence
        let (_output1, resize1) = parser.process_bytes(b"\x1b[8;24;80t");
        assert_eq!(resize1, Some(WindowResizeData { rows: 24, cols: 80 }));

        // Should be reset and ready for another sequence
        let (_output2, resize2) = parser.process_bytes(b"\x1b[8;30;120t");
        assert_eq!(
            resize2,
            Some(WindowResizeData {
                rows: 30,
                cols: 120
            })
        );
    }

    #[test]
    fn test_escape_parser_with_vim_session() {
        let mut parser = EscapeParser::new();

        // Key sequences from vim session - extracted from raw-full-vim.log
        // This focuses on the alternate screen sequences
        let vim_fixture = b"vi $HOME/bin/test.sh\n\x1b[?1049h\x1b[>4;2m\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\x1b[1;24r\x1b[?12h\x1b[?12l...vim content...\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[?1049l\x1b[?25h\x1b[>4;m";

        let actions = parser.parse(vim_fixture);

        println!("Parser state: {:?}", parser.state);
        println!("Detected actions: {:?}", actions);

        // Verify we detect both enter and exit alternate screen
        let enter_count = actions
            .iter()
            .filter(|a| **a == SequenceAction::EnterAlternateScreen)
            .count();
        let exit_count = actions
            .iter()
            .filter(|a| **a == SequenceAction::ExitAlternateScreen)
            .count();

        println!("Enter alternate screen actions: {}", enter_count);
        println!("Exit alternate screen actions: {}", exit_count);

        // For a complete vim session, we should see at least one enter and one exit
        if !vim_fixture.is_empty() {
            assert!(
                enter_count > 0,
                "Should detect vim entering alternate screen"
            );
            assert!(exit_count > 0, "Should detect vim exiting alternate screen");
        }
    }

    #[test]
    fn test_escape_parser_simple_sequences() {
        let mut parser = EscapeParser::new();

        // Test enter alternate screen
        let enter_seq = b"\x1b[?1049h";
        let actions = parser.parse(enter_seq);
        assert_eq!(actions, vec![SequenceAction::EnterAlternateScreen]);

        // Reset parser
        parser = EscapeParser::new();

        // Test exit alternate screen
        let exit_seq = b"\x1b[?1049l";
        let actions = parser.parse(exit_seq);
        assert_eq!(actions, vec![SequenceAction::ExitAlternateScreen]);

        // Reset parser
        parser = EscapeParser::new();

        // Test destructive clear
        let clear_seq = b"\x1b[3J";
        let actions = parser.parse(clear_seq);
        assert_eq!(actions, vec![SequenceAction::DestructiveClear]);
    }

    #[test]
    fn test_escape_parser_mixed_data() {
        let mut parser = EscapeParser::new();

        // Mixed data with sequences embedded
        let mixed_data = b"hello\x1b[?1049hworld\x1b[3Jtest\x1b[?1049lfoo";
        let actions = parser.parse(mixed_data);

        assert_eq!(
            actions,
            vec![
                SequenceAction::EnterAlternateScreen,
                SequenceAction::DestructiveClear,
                SequenceAction::ExitAlternateScreen
            ]
        );
    }

    // Helper function for tests that need bash PTY
    fn create_new_pty_with_bash() -> Result<(std::os::unix::io::OwnedFd, nix::unistd::Pid)> {
        create_new_pty_with_command(&["bash".to_string()])
    }

    #[test]
    fn test_multiple_sequences_in_chunk() {
        let mut parser = EscapeParser::new();

        // Your actual sequence: ESC[2J ESC[3J ESC[H
        let multi_seq = b"\x1b[2J\x1b[3J\x1b[H";

        let actions = parser.parse(multi_seq);

        println!("Multi-sequence - Parser state: {:?}", parser.state);
        println!("Multi-sequence - Detected actions: {:?}", actions);

        // Should detect the destructive clear
        assert!(actions.contains(&SequenceAction::DestructiveClear));
    }

    #[test]
    fn test_path_generation_with_default_dir() {
        // Test with default directory - just verify filename patterns without env manipulation
        // Avoids parallel test issues and /tmp assumptions
        let socket_path = get_socket_path("test-session");
        let log_path = get_log_path("test-session");
        let debug_path = get_debug_raw_log_path("test-session");
        let input_path = get_input_log_path("test-session");
        let pid_path = get_pid_file_path("test-session");

        // Verify filename patterns without assuming specific base directory
        assert!(socket_path.to_string_lossy().ends_with("test-session.sock"));
        assert!(log_path.to_string_lossy().ends_with("test-session.log"));
        assert!(
            debug_path
                .to_string_lossy()
                .ends_with("test-session-raw.log")
        );
        assert!(
            input_path
                .to_string_lossy()
                .ends_with("test-session-input.log")
        );
        assert!(pid_path.to_string_lossy().ends_with("test-session.pid"));
    }

    #[test]
    fn test_path_generation_with_custom_dir() {
        use tempfile::tempdir;

        // Test with custom directory using tempdir - no global state changes
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path();

        let socket_path = get_socket_path_in_dir("mysession", base_path);
        let log_path = get_log_path_in_dir("mysession", base_path);
        let debug_path = get_debug_raw_log_path_in_dir("mysession", base_path);
        let input_path = get_input_log_path_in_dir("mysession", base_path);

        assert_eq!(socket_path, base_path.join("mysession.sock"));
        assert_eq!(log_path, base_path.join("mysession.log"));
        assert_eq!(debug_path, base_path.join("mysession-raw.log"));
        assert_eq!(input_path, base_path.join("mysession-input.log"));

        // No cleanup needed - tempdir handles it automatically
    }

    #[test]
    fn test_term_replay_dir_environment_variable() {
        // Test that TERM_REPLAY_DIR environment variable is respected
        let old_value = std::env::var("TERM_REPLAY_DIR").ok();
        let custom_dir = "/var/run/user/1000";

        // SAFETY: Setting environment variables in tests is safe as long as:
        // 1. We restore the original value afterward
        // 2. We're only modifying test-specific variables
        // 3. This is a single-threaded test operation
        // Note: This can still race with parallel tests, but that's an acceptable test limitation
        unsafe {
            std::env::set_var("TERM_REPLAY_DIR", custom_dir);
        }

        let socket_path = get_socket_path("env-test");
        let log_path = get_log_path("env-test");
        let debug_path = get_debug_raw_log_path("env-test");
        let input_path = get_input_log_path("env-test");
        let pid_path = get_pid_file_path("env-test");

        // Verify paths use the custom directory from environment variable
        assert_eq!(
            socket_path,
            PathBuf::from("/var/run/user/1000/env-test.sock")
        );
        assert_eq!(log_path, PathBuf::from("/var/run/user/1000/env-test.log"));
        assert_eq!(
            debug_path,
            PathBuf::from("/var/run/user/1000/env-test-raw.log")
        );
        assert_eq!(
            input_path,
            PathBuf::from("/var/run/user/1000/env-test-input.log")
        );
        assert_eq!(pid_path, PathBuf::from("/var/run/user/1000/env-test.pid"));

        // Restore original environment to avoid affecting other tests
        // SAFETY: Same safety rationale as above - restoring original state
        unsafe {
            match old_value {
                Some(value) => std::env::set_var("TERM_REPLAY_DIR", value),
                None => std::env::remove_var("TERM_REPLAY_DIR"),
            }
        }
    }

    #[test]
    fn test_default_session_name() {
        // Test default session name behavior - no environment manipulation needed
        let socket_path = get_socket_path("term-replay");
        let log_path = get_log_path("term-replay");

        assert!(socket_path.to_string_lossy().ends_with("term-replay.sock"));
        assert!(log_path.to_string_lossy().ends_with("term-replay.log"));
    }

    #[test]
    fn test_session_name_with_special_characters() {
        // Test session names with various characters - no environment manipulation needed
        let socket_path = get_socket_path("my-work_session.123");
        assert!(
            socket_path
                .to_string_lossy()
                .ends_with("my-work_session.123.sock")
        );

        let socket_path = get_socket_path("dev");
        assert!(socket_path.to_string_lossy().ends_with("dev.sock"));
    }

    #[test]
    fn test_create_pty_with_custom_command() {
        // Test creating PTY with a simple command that should exist on most systems
        let command = vec!["echo".to_string(), "hello".to_string()];
        let result = create_new_pty_with_command(&command);

        assert!(
            result.is_ok(),
            "Should be able to create PTY with echo command"
        );

        if let Ok((pty_master, child_pid)) = result {
            // Verify we got valid file descriptor and PID
            assert!(
                pty_master.as_raw_fd() > 0,
                "PTY master should have valid fd"
            );
            assert!(child_pid.as_raw() > 0, "Child PID should be positive");

            // Clean up the child process
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
            let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }

    #[test]
    fn test_create_pty_with_invalid_command() {
        // Test creating PTY with a command that doesn't exist
        // With bash -c, the PTY will be created but the command will fail inside
        // This is actually the correct behavior - the error will be visible to the client
        let command = vec!["nonexistent_command_12345".to_string()];
        let result = create_new_pty_with_command(&command);

        // PTY creation should succeed, but the command will fail and client will see the error
        assert!(
            result.is_ok(),
            "PTY creation should succeed, command error will be visible to client"
        );

        if let Ok((pty_master, child_pid)) = result {
            // Verify we got valid file descriptor and PID
            assert!(
                pty_master.as_raw_fd() > 0,
                "PTY master should have valid fd"
            );
            assert!(child_pid.as_raw() > 0, "Child PID should be positive");

            // Clean up the child process
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
            let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }

    #[test]
    fn test_create_pty_with_empty_command() {
        // Test creating PTY with empty command
        let command = vec![];
        let result = create_new_pty_with_command(&command);

        assert!(result.is_err(), "Should fail with empty command");
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_create_pty_with_command_arguments() {
        // Test creating PTY with command and arguments (bash -c "ls -la")
        let command = vec!["ls".to_string(), "-la".to_string()];
        let result = create_new_pty_with_command(&command);

        assert!(
            result.is_ok(),
            "Should be able to create PTY with ls command"
        );

        if let Ok((pty_master, child_pid)) = result {
            // Verify we got valid file descriptor and PID
            assert!(
                pty_master.as_raw_fd() > 0,
                "PTY master should have valid fd"
            );
            assert!(child_pid.as_raw() > 0, "Child PID should be positive");

            // Clean up the child process
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
            let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }

    #[test]
    fn test_create_pty_with_complex_command() {
        // Test creating PTY with complex command that includes quotes and pipes
        let command = vec![
            "echo".to_string(),
            "Hello World".to_string(),
            "|".to_string(),
            "cat".to_string(),
        ];
        let result = create_new_pty_with_command(&command);

        assert!(
            result.is_ok(),
            "Should be able to create PTY with complex command"
        );

        if let Ok((pty_master, child_pid)) = result {
            // Verify we got valid file descriptor and PID
            assert!(
                pty_master.as_raw_fd() > 0,
                "PTY master should have valid fd"
            );
            assert!(child_pid.as_raw() > 0, "Child PID should be positive");

            // Clean up the child process
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
            let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }

    #[test]
    fn test_backward_compatibility_bash_wrapper() {
        // Test that the bash wrapper still works for tests
        let result = create_new_pty_with_bash();
        assert!(result.is_ok(), "Bash wrapper should still work for tests");

        if let Ok((pty_master, child_pid)) = result {
            // Verify we got valid file descriptor and PID
            assert!(
                pty_master.as_raw_fd() > 0,
                "PTY master should have valid fd"
            );
            assert!(child_pid.as_raw() > 0, "Child PID should be positive");

            // Clean up the child process
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
            let _ = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }

    // Helper function to get a PID that's guaranteed not to exist
    // Uses a short-lived child process that exits immediately
    fn get_stale_pid() -> u32 {
        use std::process::Command;

        // Spawn a process that exits immediately
        let child = Command::new("true")
            .spawn()
            .expect("Failed to spawn test process");
        let pid = child.id();

        // Wait for it to exit
        let mut child = child;
        child.wait().expect("Failed to wait for test process");

        // Now we have a PID that definitely existed but is now dead
        pid
    }

    #[test]
    fn test_pid_file_path_generation() {
        use tempfile::tempdir;

        // Test with default directory - no environment manipulation needed
        let pid_file_path = get_pid_file_path("test-session");
        assert!(
            pid_file_path
                .to_string_lossy()
                .ends_with("test-session.pid")
        );

        // Test with custom directory using tempdir - no global state changes
        let temp_dir = tempdir().unwrap();
        let pid_file_path = get_pid_file_path_in_dir("mysession", temp_dir.path());

        assert!(pid_file_path.to_string_lossy().ends_with("mysession.pid"));
        assert!(pid_file_path.starts_with(temp_dir.path()));

        // No cleanup needed - tempdir handles it automatically
    }

    #[test]
    fn test_session_state_detection() {
        // Test basic session state logic without actually creating files
        // This tests the enum and basic logic structure
        assert_eq!(SessionState::Available, SessionState::Available);
        assert_ne!(SessionState::Available, SessionState::OrphanSocket);

        // Test that we can construct the variants
        let _active = SessionState::ActiveSession(12345);
        let _stale = SessionState::StaleSession(12345);
        let _orphan = SessionState::OrphanSocket;
    }

    #[test]
    fn test_read_pid_file_edge_cases() {
        use std::fs;
        use tempfile::{NamedTempFile, tempdir};

        // Test non-existent file using tempdir
        let temp_dir = tempdir().unwrap();
        let non_existent = temp_dir.path().join("non_existent_pid_file.pid");
        assert_eq!(read_pid_file(&non_existent), None);

        // Test valid PID file
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "12345").unwrap();
        assert_eq!(read_pid_file(temp_file.path()), Some(12345));

        // Test invalid PID file (non-numeric)
        let temp_file2 = NamedTempFile::new().unwrap();
        fs::write(temp_file2.path(), "not_a_number").unwrap();
        assert_eq!(read_pid_file(temp_file2.path()), None);

        // Test empty PID file
        let temp_file3 = NamedTempFile::new().unwrap();
        fs::write(temp_file3.path(), "").unwrap();
        assert_eq!(read_pid_file(temp_file3.path()), None);

        // Test whitespace handling
        let temp_file4 = NamedTempFile::new().unwrap();
        fs::write(temp_file4.path(), "  54321  \n").unwrap();
        assert_eq!(read_pid_file(temp_file4.path()), Some(54321));
    }

    #[test]
    fn test_session_name_validation() {
        // Valid session names
        assert!(validate_session_name("valid-session").is_ok());
        assert!(validate_session_name("session123").is_ok());
        assert!(validate_session_name("my_session").is_ok());
        assert!(validate_session_name("session.backup").is_ok());
        assert!(validate_session_name("a").is_ok()); // single character
        assert!(validate_session_name("ABC123").is_ok()); // uppercase
        assert!(validate_session_name("test-123_session.v2").is_ok()); // complex valid name

        // Invalid session names - empty
        assert!(validate_session_name("").is_err());

        // Invalid session names - starts with forbidden characters
        assert!(validate_session_name(".hidden-session").is_err());
        assert!(validate_session_name("-starts-with-dash").is_err());

        // Invalid session names - contains forbidden characters
        assert!(validate_session_name("session/with/slash").is_err());
        assert!(validate_session_name("session\\with\\backslash").is_err());
        assert!(validate_session_name("session with space").is_err());
        assert!(validate_session_name("session@email").is_err());
        assert!(validate_session_name("session#hash").is_err());
        assert!(validate_session_name("session$dollar").is_err());
        assert!(validate_session_name("session%percent").is_err());
        assert!(validate_session_name("session^caret").is_err());
        assert!(validate_session_name("session&ampersand").is_err());
        assert!(validate_session_name("session*asterisk").is_err());
        assert!(validate_session_name("session(paren").is_err());
        assert!(validate_session_name("session)paren").is_err());
        assert!(validate_session_name("session+plus").is_err());
        assert!(validate_session_name("session=equals").is_err());
        assert!(validate_session_name("session[bracket").is_err());
        assert!(validate_session_name("session]bracket").is_err());
        assert!(validate_session_name("session{brace").is_err());
        assert!(validate_session_name("session}brace").is_err());
        assert!(validate_session_name("session|pipe").is_err());
        assert!(validate_session_name("session:colon").is_err());
        assert!(validate_session_name("session;semicolon").is_err());
        assert!(validate_session_name("session\"quote").is_err());
        assert!(validate_session_name("session'apostrophe").is_err());
        assert!(validate_session_name("session<less").is_err());
        assert!(validate_session_name("session>greater").is_err());
        assert!(validate_session_name("session,comma").is_err());
        assert!(validate_session_name("session?question").is_err());
        assert!(validate_session_name("session`backtick").is_err());
        assert!(validate_session_name("session~tilde").is_err());

        // Invalid session names - directory traversal
        assert!(validate_session_name("session..with..dots").is_err());
        assert!(validate_session_name("..").is_err());
        assert!(validate_session_name("session..").is_err());
        assert!(validate_session_name("..session").is_err());

        // Invalid session names - Unicode and control characters
        assert!(validate_session_name("session🎉emoji").is_err());
        assert!(validate_session_name("sessionñunicode").is_err());
        assert!(validate_session_name("session\t\ttab").is_err());
        assert!(validate_session_name("session\n\nnewline").is_err());
        assert!(validate_session_name("session\r\nwindows").is_err());

        // Too long session name
        let long_name = "a".repeat(101);
        assert!(validate_session_name(&long_name).is_err());

        // Maximum allowed length should work
        let max_name = "a".repeat(100);
        assert!(validate_session_name(&max_name).is_ok());
    }

    #[test]
    fn test_socket_guard_cleanup() {
        use tempfile::NamedTempFile;

        // Create a temporary file to simulate a socket
        let temp_file = NamedTempFile::new().unwrap();
        let socket_path = temp_file.path().to_path_buf();

        // Ensure the file exists initially
        assert!(socket_path.exists());

        {
            // Create guard - should clean up when dropped
            let _guard = SocketGuard::new(socket_path.clone());
            assert!(socket_path.exists()); // File should still exist
        } // Guard drops here

        // File should be cleaned up after guard drop
        assert!(!socket_path.exists());
    }

    #[test]
    fn test_socket_guard_disarm() {
        use tempfile::NamedTempFile;

        // Create a temporary file to simulate a socket
        let temp_file = NamedTempFile::new().unwrap();
        let socket_path = temp_file.path().to_path_buf();

        // Ensure the file exists initially
        assert!(socket_path.exists());

        {
            let mut guard = SocketGuard::new(socket_path.clone());
            guard.disarm(); // Disable cleanup
        } // Guard drops here but shouldn't clean up

        // File should still exist after disarmed guard drop
        assert!(socket_path.exists());
    }

    #[test]
    fn test_check_session_state_available() {
        use tempfile::tempdir;

        // Test SessionState::Available - no files exist
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        let state = check_session_state(&socket_path, &pid_file_path);
        assert_eq!(state, SessionState::Available);
    }

    #[test]
    fn test_check_session_state_orphan_socket() {
        use std::fs;
        use tempfile::tempdir;

        // Test SessionState::OrphanSocket - socket exists, no PID file
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create socket file but no PID file
        fs::write(&socket_path, "").unwrap();

        let state = check_session_state(&socket_path, &pid_file_path);
        assert_eq!(state, SessionState::OrphanSocket);
    }

    #[test]
    fn test_check_session_state_orphan_socket_invalid_pid() {
        use std::fs;
        use tempfile::tempdir;

        // Test SessionState::OrphanSocket - socket exists, PID file has invalid data
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create socket file and PID file with invalid data
        fs::write(&socket_path, "").unwrap();
        fs::write(&pid_file_path, "not_a_number").unwrap();

        let state = check_session_state(&socket_path, &pid_file_path);
        assert_eq!(state, SessionState::OrphanSocket);
    }

    #[test]
    fn test_check_session_state_active_session() {
        use std::fs;
        use tempfile::tempdir;

        // Test SessionState::ActiveSession - socket exists, PID exists and process is running
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create socket file and PID file with our own PID (guaranteed to be running)
        fs::write(&socket_path, "").unwrap();
        let current_pid = std::process::id();
        fs::write(&pid_file_path, current_pid.to_string()).unwrap();

        let state = check_session_state(&socket_path, &pid_file_path);
        assert_eq!(state, SessionState::ActiveSession(current_pid));
    }

    #[test]
    fn test_check_session_state_stale_session() {
        use std::fs;
        use tempfile::tempdir;

        // Test SessionState::StaleSession - socket exists, PID exists but process is dead
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create socket file and PID file with a PID that's guaranteed to be stale
        fs::write(&socket_path, "").unwrap();
        let stale_pid = get_stale_pid();
        fs::write(&pid_file_path, stale_pid.to_string()).unwrap();

        let state = check_session_state(&socket_path, &pid_file_path);
        assert_eq!(state, SessionState::StaleSession(stale_pid));
    }

    #[test]
    fn test_cleanup_stale_session() {
        use std::fs;
        use tempfile::tempdir;

        // Test cleanup_stale_session removes both socket and PID files
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create both files
        fs::write(&socket_path, "socket data").unwrap();
        fs::write(&pid_file_path, "12345").unwrap();

        // Verify files exist
        assert!(socket_path.exists());
        assert!(pid_file_path.exists());

        // Clean up
        cleanup_stale_session(&socket_path, &pid_file_path).unwrap();

        // Verify files are gone
        assert!(!socket_path.exists());
        assert!(!pid_file_path.exists());
    }

    #[test]
    fn test_cleanup_stale_session_partial_files() {
        use std::fs;
        use tempfile::tempdir;

        // Test cleanup_stale_session handles missing files gracefully
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Create only socket file
        fs::write(&socket_path, "socket data").unwrap();
        // PID file doesn't exist

        // Verify initial state
        assert!(socket_path.exists());
        assert!(!pid_file_path.exists());

        // Clean up should succeed even with missing PID file
        cleanup_stale_session(&socket_path, &pid_file_path).unwrap();

        // Verify socket is gone
        assert!(!socket_path.exists());
        assert!(!pid_file_path.exists());
    }

    #[test]
    fn test_cleanup_stale_session_no_files() {
        use tempfile::tempdir;

        // Test cleanup_stale_session handles no files gracefully
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let pid_file_path = temp_dir.path().join("test.pid");

        // Neither file exists
        assert!(!socket_path.exists());
        assert!(!pid_file_path.exists());

        // Clean up should succeed even with no files
        cleanup_stale_session(&socket_path, &pid_file_path).unwrap();

        // Should still not exist
        assert!(!socket_path.exists());
        assert!(!pid_file_path.exists());
    }

    #[test]
    fn test_create_pid_file_functionality() {
        use std::fs;
        use tempfile::tempdir;

        // Test create_pid_file creates file with correct content
        let temp_dir = tempdir().unwrap();
        let pid_file_path = temp_dir.path().join("test.pid");
        let test_pid = 12345u32;

        // Create PID file
        create_pid_file(&pid_file_path, test_pid).unwrap();

        // Verify file exists and has correct content
        assert!(pid_file_path.exists());
        let content = fs::read_to_string(&pid_file_path).unwrap();
        assert_eq!(content, "12345");

        // Verify file can be read back by our reader
        assert_eq!(read_pid_file(&pid_file_path), Some(test_pid));
    }

    #[test]
    #[cfg(unix)]
    fn test_create_pid_file_permissions() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        // Test PID file has correct permissions on Unix
        let temp_dir = tempdir().unwrap();
        let pid_file_path = temp_dir.path().join("test.pid");
        let test_pid = 12345u32;

        // Create PID file
        create_pid_file(&pid_file_path, test_pid).unwrap();

        // Check permissions (should be 0o600 = owner read/write only)
        let metadata = fs::metadata(&pid_file_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_create_pid_file_with_nested_directory() {
        use std::fs;
        use tempfile::tempdir;

        // Test create_pid_file creates nested directories if they don't exist
        let temp_dir = tempdir().unwrap();
        let nested_dir = temp_dir
            .path()
            .join("nested")
            .join("deep")
            .join("directory");
        let pid_file_path = nested_dir.join("test.pid");
        let test_pid = 12345u32;

        // Ensure nested directory doesn't exist initially
        assert!(!nested_dir.exists());

        // Create PID file - should create directories automatically
        create_pid_file(&pid_file_path, test_pid).unwrap();

        // Verify directory was created
        assert!(nested_dir.exists());

        // Verify PID file exists and has correct content
        assert!(pid_file_path.exists());
        let content = fs::read_to_string(&pid_file_path).unwrap();
        assert_eq!(content, "12345");
    }

    #[test]
    fn test_create_pid_file_directory_creation_success() {
        use std::fs;
        use tempfile::tempdir;

        // Test create_pid_file successfully creates directories when possible
        let temp_dir = tempdir().unwrap();
        let nested_path = temp_dir.path().join("some").join("nested").join("path");
        let pid_file_path = nested_path.join("test.pid");
        let test_pid = 54321u32;

        // Ensure nested path doesn't exist initially
        assert!(!nested_path.exists());

        // Create PID file - should create all necessary directories
        create_pid_file(&pid_file_path, test_pid).unwrap();

        // Verify everything was created correctly
        assert!(nested_path.exists());
        assert!(nested_path.is_dir());
        assert!(pid_file_path.exists());

        let content = fs::read_to_string(&pid_file_path).unwrap();
        assert_eq!(content, "54321");
    }

    #[test]
    fn test_full_session_lifecycle() {
        use std::fs;
        use tempfile::tempdir;

        // Test complete session lifecycle: Available -> Active -> Stale -> Cleanup -> Available
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("lifecycle.sock");
        let pid_file_path = temp_dir.path().join("lifecycle.pid");

        // 1. Initial state should be Available
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::Available
        );

        // 2. Create active session (socket + running PID)
        fs::write(&socket_path, "").unwrap();
        let current_pid = std::process::id();
        fs::write(&pid_file_path, current_pid.to_string()).unwrap();

        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::ActiveSession(current_pid)
        );

        // 3. Simulate process death by changing to stale PID
        let stale_pid = get_stale_pid();
        fs::write(&pid_file_path, stale_pid.to_string()).unwrap();

        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::StaleSession(stale_pid)
        );

        // 4. Clean up stale session
        cleanup_stale_session(&socket_path, &pid_file_path).unwrap();

        // 5. Should be Available again
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::Available
        );
    }

    #[test]
    fn test_session_state_transitions_with_edge_cases() {
        use std::fs;
        use tempfile::tempdir;

        // Test various edge cases in session state transitions
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("edge.sock");
        let pid_file_path = temp_dir.path().join("edge.pid");

        // Test empty PID file
        fs::write(&socket_path, "").unwrap();
        fs::write(&pid_file_path, "").unwrap();
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::OrphanSocket
        );

        // Test PID file with whitespace
        fs::write(&pid_file_path, "  12345  \n").unwrap();
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::StaleSession(12345)
        );

        // Test PID file with invalid characters
        fs::write(&pid_file_path, "123abc").unwrap();
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::OrphanSocket
        );

        // Test PID 0 (special case - might be kernel/system process)
        fs::write(&pid_file_path, "0").unwrap();
        let state = check_session_state(&socket_path, &pid_file_path);
        // PID 0 might be ActiveSession (kernel process) or StaleSession depending on OS
        assert!(
            matches!(state, SessionState::StaleSession(0))
                || matches!(state, SessionState::ActiveSession(0)),
            "PID 0 should be either Active or Stale, got: {:?}",
            state
        );
    }

    #[test]
    fn test_real_unix_socket_integration() {
        use tempfile::tempdir;
        use tokio::net::UnixListener;

        // Create a test that actually binds a Unix socket
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("integration-test.sock");
        let pid_file_path = temp_dir.path().join("integration-test.pid");

        // Test 1: Available state with no socket
        assert_eq!(
            check_session_state(&socket_path, &pid_file_path),
            SessionState::Available
        );

        // Test 2: Create a real Unix socket (this will verify filesystem behavior)
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // Bind a real Unix socket
            let _listener = UnixListener::bind(&socket_path).expect("Failed to bind Unix socket");

            // Verify socket file exists and has correct type
            assert!(socket_path.exists());
            let metadata = std::fs::metadata(&socket_path).unwrap();

            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                assert!(
                    metadata.file_type().is_socket(),
                    "Should be a socket file type"
                );
            }

            // Test 3: Without PID file, should be OrphanSocket
            assert_eq!(
                check_session_state(&socket_path, &pid_file_path),
                SessionState::OrphanSocket
            );

            // Test 4: With PID file, should be ActiveSession or StaleSession
            let current_pid = std::process::id();
            std::fs::write(&pid_file_path, current_pid.to_string()).unwrap();

            let state = check_session_state(&socket_path, &pid_file_path);
            assert!(
                matches!(state, SessionState::ActiveSession(_)),
                "Should be ActiveSession with real socket and current PID"
            );

            // Socket is automatically cleaned up when _listener is dropped
        });

        // Test 5: After socket is closed, cleanup should work
        cleanup_stale_session(&socket_path, &pid_file_path).unwrap();
        assert!(!socket_path.exists());
        assert!(!pid_file_path.exists());
    }

    #[test]
    fn test_process_existence_check_interface() {
        // Test that the process checking interface works across platforms

        // Test with current process (should exist on all platforms)
        let current_pid = std::process::id();
        assert!(is_process_running(current_pid));

        // Test with a PID that's guaranteed not to exist
        let stale_pid = get_stale_pid();
        let result = is_process_running(stale_pid);

        // Process should not be running since it exited
        assert!(!result, "Stale PID should not exist");
    }
}
