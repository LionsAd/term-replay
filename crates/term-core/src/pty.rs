use anyhow::Result;
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use tracing;

/// Create a new PTY with command - returns (pty_master, child_pid)
pub fn create_new_pty_with_command(
    command: &[String],
) -> Result<(OwnedFd, nix::unistd::Pid)> {
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

/// Apply window size to PTY file descriptor
pub fn apply_window_size_to_pty(pty_fd: RawFd, rows: u16, cols: u16) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pty_with_command() {
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
    fn test_create_pty_with_empty_command() {
        // Test creating PTY with empty command
        let command = vec![];
        let result = create_new_pty_with_command(&command);

        assert!(result.is_err(), "Should fail with empty command");
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }
}