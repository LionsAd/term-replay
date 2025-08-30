// src/main.rs

mod signals;
mod terminal;
mod winsize;

use anyhow::Result;
use clap::{Parser, Subcommand};
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use tokio::fs::{File as TokioFile, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, unix::AsyncFd};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast};

use signals::SignalManager;
use terminal::TerminalState;
use winsize::{WindowSizeManager, get_terminal_size};

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

const SOCKET_PATH: &str = "/tmp/term-replay.sock";
const LOG_PATH: &str = "/tmp/term-replay.log";
const DEBUG_RAW_LOG_PATH: &str = "/tmp/term-replay-raw.log";
const INPUT_LOG_PATH: &str = "/tmp/term-replay-input.log";

// Debug flag - set to true to enable raw logging
const DEBUG_RAW_LOGGING: bool = true;
const INPUT_LOGGING: bool = true;

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
    Server,
    /// Attach to the persistent terminal server
    Client {
        /// Set the detach character (default: Ctrl-\). Use '^?' for DEL, '^X' for Ctrl-X
        #[arg(short = 'e', long = "escape", value_name = "CHAR")]
        detach_char: Option<String>,
    },
}

// SERVER LOGIC
async fn server_main() -> Result<()> {
    // Initialize signal manager for server mode
    let signal_manager = SignalManager::new(false);
    signal_manager.setup_server_signals()?;

    // Initialize window size manager with defaults for server
    let window_manager = WindowSizeManager::new();

    // Clean up previous runs
    if Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH)?;
    }
    if Path::new(LOG_PATH).exists() {
        std::fs::remove_file(LOG_PATH)?;
    }
    if DEBUG_RAW_LOGGING && Path::new(DEBUG_RAW_LOG_PATH).exists() {
        std::fs::remove_file(DEBUG_RAW_LOG_PATH)?;
    }
    if INPUT_LOGGING && Path::new(INPUT_LOG_PATH).exists() {
        std::fs::remove_file(INPUT_LOG_PATH)?;
    }

    // 1. Create the Pseudo-Terminal (PTY)
    // This is a synchronous, low-level call.
    let pty_master = match unsafe { forkpty(None, None)? } {
        ForkptyResult::Parent { master, child } => {
            tracing::info!(
                "PTY created. Master fd: {}, Child pid: {}",
                master.as_raw_fd(),
                child
            );
            // In parent process, we continue.
            master
        }
        ForkptyResult::Child => {
            // In child process, we execute a shell.
            let shell_path = CString::new("/bin/bash")?;

            // --- THIS IS THE FIX ---
            // The leading dash tells bash to run as a login shell.
            let shell_arg0 = CString::new("-bash")?;

            // The first argument in the `args` array is what the program
            // sees as its own name (`argv[0]`).
            let args = [shell_arg0.as_c_str()];

            // We still execute the program at `/bin/bash`
            unistd::execvp(&shell_path, &args)?;
            // execvp replaces the current process, so this is unreachable
            unreachable!();
        }
    };

    // 2. Setup Async Wrappers and Channels
    // Make the PTY master file descriptor non-blocking for use with tokio
    let pty_master_fd = pty_master.as_raw_fd();
    nix::fcntl::fcntl(
        pty_master_fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )?;

    // Apply initial window size to PTY
    window_manager.apply_to_fd(pty_master_fd)?;

    // Use AsyncFd for proper async I/O with PTY
    let pty_async = AsyncFd::new(pty_master_fd)?;
    let pty_async = Arc::new(pty_async);

    let listener = UnixListener::bind(SOCKET_PATH)?;
    let log_file = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_PATH)
            .await?,
    ));

    // Debug raw log file (logs ALL data, unfiltered)
    let debug_raw_log = if DEBUG_RAW_LOGGING {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(DEBUG_RAW_LOG_PATH)
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
                .open(INPUT_LOG_PATH)
                .await?,
        )))
    } else {
        None
    };

    // Broadcast channel to send PTY output to all connected clients
    let (tx, _) = broadcast::channel::<Vec<u8>>(1024);

    // 3. PTY Reader Task
    // This task reads from the PTY master and distributes the output.
    let tx_clone = tx.clone();
    let pty_async_clone = pty_async.clone();
    let debug_raw_log_clone = debug_raw_log.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let mut parser = EscapeParser::new();
        let mut terminal_mode = TerminalMode::Normal;

        loop {
            let mut guard = pty_async_clone.readable().await.unwrap();
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
                    tracing::info!("PTY master EOF. Shell process likely exited.");
                    // Reset terminal mode on EOF (handles crashed applications)
                    terminal_mode = TerminalMode::Normal;
                    break;
                }
                Ok(Ok(n)) => {
                    let data = buf[..n].to_vec();

                    // 1. ALWAYS forward raw data to clients and raw debug log
                    // This happens FIRST, unconditionally

                    // Raw debug logging - write ALL data unconditionally
                    if let Some(debug_log) = &debug_raw_log_clone {
                        let mut debug = debug_log.lock().await;
                        if let Err(e) = debug.write_all(&data).await {
                            tracing::error!("Failed to write to debug raw log: {}", e);
                        }
                    }

                    // Always broadcast to all clients (they see everything live)
                    if tx_clone.send(data.clone()).is_err() {
                        // This means no clients are connected, which is fine.
                    }

                    // 2. SEPARATE filtered logging pipeline
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
    });

    // 4. Main Accept Loop with Signal Handling
    // This loop waits for new clients to connect and handles window size changes.
    tracing::info!("Server listening on {}", SOCKET_PATH);
    loop {
        // Server window size changes are handled per-client via escape sequences

        // Check for shutdown signal
        if signal_manager.check_shutdown_requested() {
            if let Some(sig) = signal_manager.get_shutdown_signal() {
                tracing::info!("Received shutdown signal: {:?}, terminating server", sig);
            }
            return Ok(());
        }

        tokio::select! {
            // Accept new client connections
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        tracing::info!("New client connected");
                        let pty_async_clone = pty_async.clone();
                        let input_log_clone = input_log.clone();
                        let mut rx = tx.subscribe();

                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, pty_async_clone, input_log_clone, &mut rx).await {
                                tracing::warn!("Client disconnected with error: {}", e);
                            } else {
                                tracing::info!("Client disconnected gracefully.");
                            }
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
    pty_async: Arc<AsyncFd<RawFd>>,
    input_log: Option<Arc<Mutex<TokioFile>>>,
    rx: &mut broadcast::Receiver<Vec<u8>>,
) -> Result<()> {
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);

    // Initialize input parser for this client
    let mut input_parser = InputParser::new();

    // a. Replay history
    let mut history_file = TokioFile::open(LOG_PATH).await?;
    tokio::io::copy(&mut history_file, &mut client_writer).await?;

    loop {
        let mut client_buf = [0u8; 1024];

        tokio::select! {
            // b. Read from client (stdin) and write to PTY
            result = client_reader.read(&mut client_buf) => {
                match result {
                    Ok(0) => break, // Client disconnected
                    Ok(n) => {
                        let input_data = &client_buf[..n];

                        // Process input through state machine to detect resize sequences
                        let (data_to_forward, resize_data) = input_parser.process_bytes(input_data);

                        // Handle resize if detected
                        if let Some(resize) = resize_data {
                            tracing::debug!("Detected window resize: {}x{}", resize.cols, resize.rows);

                            // Apply new window size to PTY
                            if let Err(e) = apply_window_size_to_pty(pty_async.get_ref().as_raw_fd(), resize.rows, resize.cols) {
                                tracing::warn!("Failed to apply window size to PTY: {}", e);
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

                            // Forward processed data to PTY
                            let mut guard = pty_async.writable().await.unwrap();
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
                    Ok(data) => {
                        client_writer.write_all(&data).await?;
                    }
                    Err(e) => {
                        tracing::error!("Broadcast channel error: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

// CLIENT LOGIC
async fn client_main(detach_char: u8) -> Result<()> {
    // Initialize signal manager for client mode
    let signal_manager = SignalManager::new(true);
    signal_manager.setup_client_signals()?;

    // Initialize terminal state
    let mut terminal_state = TerminalState::new()?;
    if !terminal_state.is_terminal_available() {
        anyhow::bail!("Attaching to a session requires a terminal.");
    }

    // Get initial window size
    let initial_window_size = get_terminal_size();
    let mut window_manager = WindowSizeManager::new();
    window_manager.update_size(initial_window_size);

    if !Path::new(SOCKET_PATH).exists() {
        anyhow::bail!(
            "Server socket not found at {}. Is the server running?",
            SOCKET_PATH
        );
    }

    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (mut server_reader, mut server_writer) = tokio::io::split(stream);

    // Enter raw terminal mode for proper terminal control
    terminal_state.enter_raw_mode()?;

    // Clear screen and position cursor at bottom
    print!("\x1b[H\x1b[J");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // Enhanced client loop with signal handling
    let mut stdin_buf = [0u8; 1024];
    let mut server_buf = [0u8; 1024];

    loop {
        // Check for window size changes
        if signal_manager.check_window_changed() {
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

        // Check for shutdown signal
        if signal_manager.check_shutdown_requested() {
            if let Some(sig) = signal_manager.get_shutdown_signal() {
                tracing::info!("Received shutdown signal: {:?}", sig);
            }
            break;
        }

        tokio::select! {
            // Handle keyboard input
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => {
                        tracing::info!("Local stdin closed");
                        break;
                    }
                    Ok(n) => {
                        // Process input for detach key
                        let input_data = &stdin_buf[..n];

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
                        if let Err(e) = server_writer.write_all(input_data).await {
                            tracing::error!("Failed to write to server: {}", e);
                            break;
                        }
                        if let Err(e) = server_writer.flush().await {
                            tracing::error!("Failed to flush server writer: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading from stdin: {}", e);
                        break;
                    }
                }
            }

            // Handle server output
            result = server_reader.read(&mut server_buf) => {
                match result {
                    Ok(0) => {
                        tracing::info!("Connection to server closed");
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

    // Terminal state will be automatically restored by Drop trait

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Server => server_main().await,
        Commands::Client { detach_char } => {
            let detach_byte = if let Some(char_str) = detach_char {
                parse_detach_char(&char_str)?
            } else {
                0x1C // Default: Ctrl-\
            };
            client_main(detach_byte).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[test]
fn test_multiple_sequences_in_chunk() {
    let mut parser = EscapeParser::new();

    // Your actual sequence: ESC[2J ESC[3J ESC[H
    let multi_seq = b"[2J[3J[H";

    let actions = parser.parse(multi_seq);

    println!("Multi-sequence - Parser state: {:?}", parser.state);
    println!("Multi-sequence - Detected actions: {:?}", actions);

    // Should detect the destructive clear
    assert!(actions.contains(&SequenceAction::DestructiveClear));
}
