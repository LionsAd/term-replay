// src/stdin.rs
// Stdin handling module using dedicated thread with proper shutdown signaling

use anyhow::Result;
use std::os::unix::io::{BorrowedFd, OwnedFd};
use std::thread::JoinHandle;
use tokio::sync::mpsc;
use tracing;

/// Handle for managing the stdin reader thread
pub struct StdinReader {
    handle: JoinHandle<()>,
    shutdown_write_fd: OwnedFd,
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl StdinReader {
    /// Create a new stdin reader that runs in a dedicated thread
    /// Returns a handle and a receiver for stdin data
    pub fn start() -> Result<Self> {
        let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Create a pipe for signaling the thread to shutdown
        let (shutdown_read_fd, shutdown_write_fd) = nix::unistd::pipe()?;

        // Spawn blocking thread for stdin using select() to wait on multiple FDs
        let handle = std::thread::spawn(move || {
            use nix::sys::select::{FdSet, select};
            use std::os::unix::io::AsRawFd;

            let stdin_fd = std::io::stdin().as_raw_fd();
            let mut buf = [0u8; 1024];

            tracing::debug!("Stdin reader thread started");

            loop {
                // Set up file descriptor sets for select()
                let mut read_fds = FdSet::new();
                let stdin_borrowed = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
                let shutdown_borrowed =
                    unsafe { BorrowedFd::borrow_raw(shutdown_read_fd.as_raw_fd()) };
                read_fds.insert(stdin_borrowed);
                read_fds.insert(shutdown_borrowed);

                // Wait for either stdin or shutdown signal
                match select(None, Some(&mut read_fds), None, None, None) {
                    Ok(_) => {
                        // Check if shutdown was signaled
                        if read_fds.contains(shutdown_borrowed) {
                            tracing::debug!("Stdin thread received shutdown signal via pipe");
                            break;
                        }

                        // Check if stdin is ready
                        if read_fds.contains(stdin_borrowed) {
                            match nix::unistd::read(stdin_fd, &mut buf) {
                                Ok(0) => {
                                    tracing::debug!("Stdin EOF detected");
                                    break;
                                }
                                Ok(n) => {
                                    let data = buf[..n].to_vec();
                                    if stdin_tx.send(data).is_err() {
                                        tracing::debug!("Stdin channel closed, exiting thread");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Stdin read error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Select error in stdin thread: {}", e);
                        break;
                    }
                }
            }

            tracing::debug!("Stdin reader thread exiting");

            // shutdown_read_fd will be automatically closed when it goes out of scope
        });

        Ok(StdinReader {
            handle,
            shutdown_write_fd,
            receiver: stdin_rx,
        })
    }

    /// Get the receiver for stdin data
    pub fn receiver(&mut self) -> &mut mpsc::UnboundedReceiver<Vec<u8>> {
        &mut self.receiver
    }

    /// Shutdown the stdin reader thread gracefully
    pub async fn shutdown(self) -> Result<()> {
        tracing::debug!("Shutting down stdin reader");

        // Signal the stdin thread to shutdown by writing to the pipe
        if let Err(e) = nix::unistd::write(&self.shutdown_write_fd, &[1u8]) {
            tracing::warn!("Failed to signal stdin thread shutdown: {}", e);
        }

        // Wait for the stdin thread to exit gracefully with a timeout
        match tokio::task::spawn_blocking(move || self.handle.join()).await {
            Ok(Ok(())) => {
                tracing::debug!("Stdin thread exited gracefully");
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::warn!("Stdin thread panicked: {:?}", e);
                anyhow::bail!("Stdin thread panicked: {:?}", e);
            }
            Err(e) => {
                tracing::warn!("Failed to join stdin thread: {}", e);
                anyhow::bail!("Failed to join stdin thread: {}", e);
            }
        }
    }
}