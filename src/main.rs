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
use terminal::{TerminalState, is_terminal};
use winsize::{WindowSizeManager, get_terminal_size};

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
    Client,
}

// SERVER LOGIC
async fn server_main() -> Result<()> {
    // Initialize signal manager for server mode
    let signal_manager = SignalManager::new(false);
    signal_manager.setup_server_signals()?;

    // Initialize window size manager
    let mut window_manager = WindowSizeManager::new();
    if is_terminal(0) {
        window_manager.init_from_terminal(0).unwrap_or_else(|_| {
            tracing::warn!("Failed to get terminal size, using defaults");
        });
    }

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
        // Check for window size changes
        if signal_manager.check_window_changed() {
            let new_size = get_terminal_size();
            if window_manager.update_size(new_size) {
                tracing::debug!(
                    "Server window size changed: {}x{}",
                    new_size.cols,
                    new_size.rows
                );
                // Apply new size to PTY
                if let Err(e) = window_manager.apply_to_fd(pty_master_fd) {
                    tracing::warn!("Failed to apply window size to PTY: {}", e);
                }
            }
        }

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

                        // Log input data (client-to-PTY)
                        if let Some(input_log) = &input_log {
                            let mut log = input_log.lock().await;
                            if let Err(e) = log.write_all(input_data).await {
                                tracing::error!("Failed to write to input log: {}", e);
                            }
                        }

                        let mut guard = pty_async.writable().await.unwrap();
                        match guard.try_io(|inner| {
                            let fd = inner.as_raw_fd();
                            unsafe {
                                let result = libc::write(fd, client_buf[..n].as_ptr() as *const libc::c_void, n);
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
async fn client_main() -> Result<()> {
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
                // TODO: Send window size change to server via protocol message
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
                        // TODO: Process detach key and other special sequences
                        if let Err(e) = server_writer.write_all(&stdin_buf[..n]).await {
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
        Commands::Client => client_main().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
