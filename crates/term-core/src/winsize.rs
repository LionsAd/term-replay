use nix::libc::winsize;
use std::io;
use std::os::unix::io::RawFd;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

impl WindowSize {
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            rows,
            cols,
            x_pixels: 0,
            y_pixels: 0,
        }
    }

    pub fn default() -> Self {
        Self::new(24, 80)
    }

    pub fn from_winsize(ws: &winsize) -> Self {
        Self {
            rows: ws.ws_row,
            cols: ws.ws_col,
            x_pixels: ws.ws_xpixel,
            y_pixels: ws.ws_ypixel,
        }
    }

    pub fn to_winsize(&self) -> winsize {
        winsize {
            ws_row: self.rows,
            ws_col: self.cols,
            ws_xpixel: self.x_pixels,
            ws_ypixel: self.y_pixels,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.rows > 0 && self.cols > 0
    }
}

/// Window size manager for tracking and broadcasting changes
pub struct WindowSizeManager {
    current_size: WindowSize,
    size_sender: broadcast::Sender<WindowSize>,
}

impl WindowSizeManager {
    pub fn new() -> Self {
        let (size_sender, _) = broadcast::channel(16);

        Self {
            current_size: WindowSize::default(),
            size_sender,
        }
    }

    /// Update window size and broadcast changes
    pub fn update_size(&mut self, new_size: WindowSize) -> bool {
        if new_size != self.current_size && new_size.is_valid() {
            self.current_size = new_size;
            // Best effort broadcast - ignore if no receivers
            let _ = self.size_sender.send(new_size);
            true
        } else {
            false
        }
    }

    /// Get current window size
    #[cfg(test)]
    pub fn current_size(&self) -> WindowSize {
        self.current_size
    }

    /// Apply window size to a file descriptor (PTY master)
    pub fn apply_to_fd(&self, fd: RawFd) -> io::Result<()> {
        let ws = self.current_size.to_winsize();
        set_window_size(fd, &ws)
    }
}

/// Get window size from file descriptor
pub fn get_window_size(fd: RawFd) -> io::Result<winsize> {
    let mut ws: winsize = unsafe { std::mem::zeroed() };

    let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, &mut ws) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Ensure we have reasonable values
    if ws.ws_row == 0 || ws.ws_col == 0 {
        ws.ws_row = 24;
        ws.ws_col = 80;
    }

    Ok(ws)
}

/// Set window size on file descriptor
pub fn set_window_size(fd: RawFd, ws: &winsize) -> io::Result<()> {
    let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, ws) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Get window size from stdin with fallback
pub fn get_terminal_size() -> WindowSize {
    match get_window_size(0) {
        Ok(ws) => WindowSize::from_winsize(&ws),
        Err(_) => WindowSize::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_size_creation() {
        let ws = WindowSize::new(25, 90);
        assert_eq!(ws.rows, 25);
        assert_eq!(ws.cols, 90);
        assert!(ws.is_valid());
    }

    #[test]
    fn test_window_size_validation() {
        assert!(WindowSize::new(24, 80).is_valid());
        assert!(!WindowSize::new(0, 80).is_valid());
        assert!(!WindowSize::new(24, 0).is_valid());
    }

    #[test]
    fn test_winsize_conversion() {
        let ws = WindowSize::new(30, 120);
        let winsize = ws.to_winsize();

        assert_eq!(winsize.ws_row, 30);
        assert_eq!(winsize.ws_col, 120);

        let converted_back = WindowSize::from_winsize(&winsize);
        assert_eq!(ws, converted_back);
    }

    #[test]
    fn test_window_size_manager() {
        let mut manager = WindowSizeManager::new();

        let initial_size = manager.current_size();
        assert_eq!(initial_size, WindowSize::default());

        let new_size = WindowSize::new(50, 100);
        assert!(manager.update_size(new_size));
        assert_eq!(manager.current_size(), new_size);

        // Should not update with same size
        assert!(!manager.update_size(new_size));

        // Should not update with invalid size
        assert!(!manager.update_size(WindowSize::new(0, 100)));
    }

    #[test]
    fn test_terminal_size_fallback() {
        // Should not panic and return reasonable defaults
        let size = get_terminal_size();
        assert!(size.is_valid());
        assert!(size.rows > 0 && size.cols > 0);
    }
}
