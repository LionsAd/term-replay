use chrono;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{unix::AsyncFd, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{broadcast, Mutex};
use tracing;

use crate::parser::{EscapeParser, SequenceAction, TerminalMode};

/// Data sent from the PTY task to client handlers.
#[derive(Debug, Clone)]
pub enum PtyOutput {
    Data(Vec<u8>),
    Shutdown,
}

/// PTY reader task that handles PTY output and manages PTY lifecycle
pub async fn pty_reader_task(
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
