use nix::sys::signal::{self, SigHandler, Signal};
use nix::unistd::{self, Pid};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Global flag to track window size changes
static WINDOW_CHANGED: AtomicBool = AtomicBool::new(false);

/// Global flag to track shutdown signals
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Store the signal that triggered shutdown
static SHUTDOWN_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Window change handler
extern "C" fn handle_winch(_: libc::c_int) {
    WINDOW_CHANGED.store(true, Ordering::Relaxed);
}

/// Shutdown signal handler
extern "C" fn handle_shutdown(sig: libc::c_int) {
    SHUTDOWN_SIGNAL.store(sig, Ordering::Relaxed);
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

/// Terminal death handler (for clients)
extern "C" fn handle_death(sig: libc::c_int) {
    const EOS: &str = "\x1b[999H";

    match sig {
        libc::SIGHUP | libc::SIGINT => {
            println!("{}\\r\\n[detached]\\r\\n", EOS);
        }
        _ => {
            println!("{}\\r\\n[got signal {} - dying]\\r\\n", EOS, sig);
        }
    }
    std::process::exit(1);
}

/// Signal manager for coordinating signal handling
pub struct SignalManager {
    /// PTY process ID for signal forwarding
    pty_pid: Option<Pid>,
    /// Client mode vs server mode
    is_client: bool,
}

impl SignalManager {
    pub fn new(is_client: bool) -> Self {
        Self {
            pty_pid: None,
            is_client,
        }
    }

    pub fn set_pty_pid(&mut self, pid: Pid) {
        self.pty_pid = Some(pid);
    }

    /// Initialize signal handlers for server mode
    pub fn setup_server_signals(&self) -> io::Result<()> {
        unsafe {
            // Set up SIGWINCH handler
            signal::signal(Signal::SIGWINCH, SigHandler::Handler(handle_winch))
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Set up shutdown signal handlers
            let shutdown_handler = SigHandler::Handler(handle_shutdown);
            signal::signal(Signal::SIGTERM, shutdown_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGINT, shutdown_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGHUP, shutdown_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Ignore signals that shouldn't terminate the server
            signal::signal(Signal::SIGPIPE, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGXFSZ, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGTTIN, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGTTOU, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Handle SIGCHLD to detect child process exit
            signal::signal(Signal::SIGCHLD, SigHandler::SigDfl)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }

        Ok(())
    }

    /// Initialize signal handlers for client mode
    pub fn setup_client_signals(&self) -> io::Result<()> {
        unsafe {
            // Set up SIGWINCH handler
            signal::signal(Signal::SIGWINCH, SigHandler::Handler(handle_winch))
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Ignore SIGPIPE
            signal::signal(Signal::SIGPIPE, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGXFSZ, SigHandler::SigIgn)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            // Set up death handlers for clean disconnect
            let death_handler = SigHandler::Handler(handle_death);
            signal::signal(Signal::SIGHUP, death_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGTERM, death_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGINT, death_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            signal::signal(Signal::SIGQUIT, death_handler)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }

        Ok(())
    }

    /// Forward signal to PTY process group
    pub fn forward_signal_to_pty(&self, sig: Signal) -> io::Result<()> {
        if let Some(pid) = self.pty_pid {
            // Try to get the process group first
            match unistd::getpgid(Some(pid)) {
                Ok(pgrp) => {
                    // Send signal to process group
                    signal::killpg(pgrp, sig)
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                }
                Err(_) => {
                    // Fallback: send to process directly
                    signal::kill(pid, sig).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                }
            }
        }
        Ok(())
    }

    /// Check and reset window size change flag
    pub fn check_window_changed(&self) -> bool {
        WINDOW_CHANGED.swap(false, Ordering::Relaxed)
    }

    /// Check if shutdown was requested
    pub fn check_shutdown_requested(&self) -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
    }

    /// Get the signal that triggered shutdown
    pub fn get_shutdown_signal(&self) -> Option<Signal> {
        let sig = SHUTDOWN_SIGNAL.load(Ordering::Relaxed);
        if sig != 0 {
            Signal::try_from(sig).ok()
        } else {
            None
        }
    }

    /// Reset shutdown state (for testing)
    pub fn reset_shutdown(&self) {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        SHUTDOWN_SIGNAL.store(0, Ordering::Relaxed);
    }
}

/// Send SIGWINCH to process/group
pub fn send_winch_to_process(pid: Pid) -> io::Result<()> {
    // Try process group first
    match unistd::getpgid(Some(pid)) {
        Ok(pgrp) => {
            signal::killpg(pgrp, Signal::SIGWINCH)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }
        Err(_) => {
            // Fallback to direct process
            signal::kill(pid, Signal::SIGWINCH)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_manager_creation() {
        let signal_manager = SignalManager::new(false);
        assert!(!signal_manager.is_client);
        assert!(signal_manager.pty_pid.is_none());
    }

    #[test]
    fn test_window_change_flag() {
        // Initially should be false
        assert!(!WINDOW_CHANGED.load(Ordering::Relaxed));

        // Simulate window change
        WINDOW_CHANGED.store(true, Ordering::Relaxed);

        let manager = SignalManager::new(false);

        // Should return true and reset to false
        assert!(manager.check_window_changed());
        assert!(!manager.check_window_changed());
    }

    #[test]
    fn test_shutdown_state() {
        let manager = SignalManager::new(false);

        // Reset state
        manager.reset_shutdown();

        assert!(!manager.check_shutdown_requested());
        assert!(manager.get_shutdown_signal().is_none());

        // Simulate shutdown signal
        SHUTDOWN_SIGNAL.store(libc::SIGTERM, Ordering::Relaxed);
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);

        assert!(manager.check_shutdown_requested());
        assert_eq!(manager.get_shutdown_signal(), Some(Signal::SIGTERM));
    }
}
