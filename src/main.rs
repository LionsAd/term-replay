// src/main.rs

use anyhow::Result;
use clap::{Parser, Subcommand};
use nix::pty::{forkpty, ForkptyResult};
use nix::unistd::{self, ForkResult};
use std::ffi::CString;
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::path::Path;
use std::sync::Arc;
use tokio::fs::{File as TokioFile, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};

const SOCKET_PATH: &str = "/tmp/term-replay.sock";
const LOG_PATH: &str = "/tmp/term-replay.log";

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
    // Clean up previous runs
    if Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH)?;
    }
    if Path::new(LOG_PATH).exists() {
        std::fs::remove_file(LOG_PATH)?;
    }

    // 1. Create the Pseudo-Terminal (PTY)
    // This is a synchronous, low-level call.
    let pty_master = match unsafe { forkpty(None, None)? } {
        ForkptyResult::Parent { master, child } => {
            tracing::info!("PTY created. Master fd: {}, Child pid: {}", master.as_raw_fd(), child);
            // In parent process, we continue.
            master
        }
        ForkptyResult::Child => {
            // In child process, we execute a shell.
            let shell = CString::new("/bin/bash")?;
            let args = [shell.as_c_str()];
            unistd::execvp(&shell, &args)?;
            // execvp replaces the current process, so this is unreachable
            unreachable!();
        }
    };

    // 2. Setup Async Wrappers and Channels
    // Make the PTY master file descriptor non-blocking for use with tokio
    let pty_master_fd = pty_master.as_raw_fd();
    nix::fcntl::fcntl(pty_master_fd, nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))?;

    // Wrap the raw fd in Tokio's async-compatible file type
    let pty_master_file = unsafe { TokioFile::from_raw_fd(pty_master_fd) };
    let (pty_reader, pty_writer) = tokio::io::split(pty_master_file);
    let pty_writer = Arc::new(Mutex::new(pty_writer));

    let listener = UnixListener::bind(SOCKET_PATH)?;
    let log_file = Arc::new(Mutex::new(
        OpenOptions::new().create(true).append(true).open(LOG_PATH).await?,
    ));

    // Broadcast channel to send PTY output to all connected clients
    let (tx, _) = broadcast::channel::<Vec<u8>>(1024);

    // 3. PTY Reader Task
    // This task reads from the PTY master and distributes the output.
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let mut pty_reader = pty_reader;
        let mut buf = [0u8; 1024];
        loop {
            match pty_reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!("PTY master EOF. Shell process likely exited.");
                    break;
                }
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    
                    // a. Write to the log file
                    if let Ok(mut log) = log_file.lock().await {
                        if let Err(e) = log.write_all(&data).await {
                            tracing::error!("Failed to write to log: {}", e);
                        }
                    }

                    // b. Broadcast to all clients
                    if tx_clone.send(data).is_err() {
                        // This means no clients are connected, which is fine.
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read from PTY master: {}", e);
                    break;
                }
            }
        }
    });

    // 4. Main Accept Loop
    // This loop waits for new clients to connect.
    tracing::info!("Server listening on {}", SOCKET_PATH);
    loop {
        let (stream, _) = listener.accept().await?;
        tracing::info!("New client connected");
        let pty_writer_clone = pty_writer.clone();
        let mut rx = tx.subscribe();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, pty_writer_clone, &mut rx).await {
                tracing::warn!("Client disconnected with error: {}", e);
            } else {
                tracing::info!("Client disconnected gracefully.");
            }
        });
    }
}

// This function manages a single client's lifecycle.
async fn handle_client(
    stream: UnixStream,
    pty_writer: Arc<Mutex<tokio::io::WriteHalf<TokioFile>>>,
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
                        pty_writer.lock().await.write_all(&client_buf[..n]).await?;
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
    if !Path::new(SOCKET_PATH).exists() {
        anyhow::bail!("Server socket not found at {}. Is the server running?", SOCKET_PATH);
    }

    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let (mut server_reader, mut server_writer) = tokio::io::split(stream);

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // Two tasks: one for stdin -> server, one for server -> stdout
    let client_to_server = tokio::spawn(async move {
        tokio::io::copy(&mut stdin, &mut server_writer).await
    });

    let server_to_client = tokio::spawn(async move {
        tokio::io::copy(&mut server_reader, &mut stdout).await
    });
    
    // Wait for either direction to finish
    tokio::select! {
        res = client_to_server => {
            tracing::info!("Local stdin closed. {:?}", res);
        }
        res = server_to_client => {
            tracing::info!("Connection to server closed. {:?}", res);
        }
    }

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
