use nix::libc::winsize;
use nix::sys::termios::{self, ControlFlags, InputFlags, LocalFlags, OutputFlags, SetArg, Termios};
use nix::unistd;
use std::io;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone)]
pub struct TerminalState {
    pub original_termios: Option<Termios>,
    pub raw_termios: Option<Termios>,
    pub is_raw: bool,
}

impl TerminalState {
    pub fn new() -> io::Result<Self> {
        let original_termios = if is_terminal(0) {
            Some(termios::tcgetattr(std::io::stdin())?)
        } else {
            None
        };

        Ok(TerminalState {
            original_termios,
            raw_termios: None,
            is_raw: false,
        })
    }

    pub fn enter_raw_mode(&mut self) -> io::Result<()> {
        if self.is_raw || self.original_termios.is_none() {
            return Ok(());
        }

        let original = self.original_termios.as_ref().unwrap().clone();
        let mut raw = original.clone();

        // Set raw mode flags (based on dtach implementation)
        raw.input_flags.remove(
            InputFlags::IGNBRK
                | InputFlags::BRKINT
                | InputFlags::PARMRK
                | InputFlags::ISTRIP
                | InputFlags::INLCR
                | InputFlags::IGNCR
                | InputFlags::ICRNL
                | InputFlags::IXON
                | InputFlags::IXOFF,
        );

        raw.output_flags.remove(OutputFlags::OPOST);

        raw.local_flags.remove(
            LocalFlags::ECHO
                | LocalFlags::ECHONL
                | LocalFlags::ICANON
                | LocalFlags::ISIG
                | LocalFlags::IEXTEN,
        );

        raw.control_flags
            .remove(ControlFlags::CSIZE | ControlFlags::PARENB);
        raw.control_flags.insert(ControlFlags::CS8);

        // Set control characters for raw mode
        raw.control_chars[termios::SpecialCharacterIndices::VLNEXT as usize] = 0;
        raw.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 1;
        raw.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 0;

        termios::tcsetattr(std::io::stdin(), SetArg::TCSADRAIN, &raw)?;

        self.raw_termios = Some(raw);
        self.is_raw = true;

        Ok(())
    }

    pub fn exit_raw_mode(&mut self) -> io::Result<()> {
        if !self.is_raw || self.original_termios.is_none() {
            return Ok(());
        }

        termios::tcsetattr(
            std::io::stdin(),
            SetArg::TCSADRAIN,
            self.original_termios.as_ref().unwrap(),
        )?;

        self.is_raw = false;

        // Make cursor visible (assumes VT100 compatibility)
        print!("\x1b[?25h");
        std::io::Write::flush(&mut std::io::stdout())?;

        Ok(())
    }

    pub fn is_terminal_available(&self) -> bool {
        self.original_termios.is_some()
    }
}

impl Drop for TerminalState {
    fn drop(&mut self) {
        let _ = self.exit_raw_mode();
    }
}

pub fn is_terminal(fd: RawFd) -> bool {
    unistd::isatty(fd).unwrap_or(false)
}

#[allow(dead_code)]
pub fn get_window_size(fd: RawFd) -> io::Result<winsize> {
    let mut ws: winsize = unsafe { std::mem::zeroed() };

    let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, &mut ws) };

    if result < 0 {
        // Return default size if ioctl fails
        ws.ws_row = 24;
        ws.ws_col = 80;
        ws.ws_xpixel = 0;
        ws.ws_ypixel = 0;
    }

    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_detection() {
        // Test with stdout (usually a terminal in interactive mode)
        let _is_stdout_terminal = is_terminal(1);

        // Test with an invalid fd
        assert!(!is_terminal(-1));
    }

    #[test]
    fn test_window_size_handling() {
        // Test getting window size (should not panic)
        let ws = get_window_size(0);
        assert!(ws.is_ok());

        let ws = ws.unwrap();
        // Should have reasonable defaults if not a terminal
        assert!(ws.ws_row > 0);
        assert!(ws.ws_col > 0);
    }

    #[test]
    fn test_terminal_state_creation() {
        // Should not panic when creating terminal state
        let terminal_state = TerminalState::new();
        assert!(terminal_state.is_ok());
    }
}
