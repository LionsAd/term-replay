use serde::{Deserialize, Serialize};

/// Parse detach character from string (e.g., "^\" -> Ctrl-\, "^?" -> DEL)
pub fn parse_detach_char(detach_str: &str) -> anyhow::Result<u8> {
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

/// Session information returned by list-sessions endpoint
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub pid: u32,
    pub created: String,
}

/// Messages sent over WebSocket for terminal I/O
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TerminalMessage {
    /// Raw terminal data (input or output)
    Data(Vec<u8>),
    /// Resize terminal
    Resize { rows: u16, cols: u16 },
    /// Session ended
    Shutdown,
}

/// Tunnel handshake constants
pub mod handshake {
    pub const TUNNEL_READY_SEQUENCE: &[u8] = b"\x1b]tunnel-ready;\x07";
}

/// Constants for logging and debugging
pub mod constants {
    pub const DEBUG_RAW_LOGGING: bool = true;
    pub const INPUT_LOGGING: bool = true;
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
    fn test_session_info_serialization() {
        let session = SessionInfo {
            id: "test-session".to_string(),
            name: "test".to_string(), 
            pid: 12345,
            created: "2025-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: SessionInfo = serde_json::from_str(&json).unwrap();
        
        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.name, deserialized.name);
        assert_eq!(session.pid, deserialized.pid);
    }
}