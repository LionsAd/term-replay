/// Window resize data
#[derive(Debug, PartialEq, Clone)]
pub struct WindowResizeData {
    pub rows: u16,
    pub cols: u16,
}

/// State machine for parsing input and detecting resize sequences
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputParseState {
    Normal,
    Escape,        // Saw ESC (\x1b)
    Csi,           // Saw ESC [
    Csi8,          // Saw ESC [ 8
    Csi8Semicolon, // Saw ESC [ 8 ;
    Rows,          // Parsing row digits
    RowsSemicolon, // Saw semicolon after rows
    Cols,          // Parsing column digits
}

/// Actions to take when processing input bytes
#[derive(Debug, PartialEq)]
pub enum InputAction {
    Forward(u8),                      // Forward this byte normally
    ForwardSequence,                  // Forward accumulated sequence buffer
    ResizeDetected(WindowResizeData), // Complete resize sequence detected
    Continue,                         // Continue accumulating sequence
}

/// Input parser for detecting resize sequences
pub struct InputParser {
    state: InputParseState,
    sequence_buffer: Vec<u8>,
    rows_str: String,
    cols_str: String,
}

impl InputParser {
    pub fn new() -> Self {
        Self {
            state: InputParseState::Normal,
            sequence_buffer: Vec::new(),
            rows_str: String::new(),
            cols_str: String::new(),
        }
    }

    /// Process input bytes and extract any complete resize sequences
    /// Returns (data_to_forward, optional_resize_data)
    pub fn process_bytes(&mut self, input: &[u8]) -> (Vec<u8>, Option<WindowResizeData>) {
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

// Terminal mode tracking
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TerminalMode {
    Normal,    // Log everything
    Alternate, // Skip logging (vim, less, etc.)
}

// Escape sequence parser state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParseState {
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
pub enum SequenceAction {
    EnterAlternateScreen,
    ExitAlternateScreen,
    DestructiveClear,
}

// Escape sequence parser
pub struct EscapeParser {
    state: ParseState,
    buffer: Vec<u8>,
}

impl EscapeParser {
    pub fn new() -> Self {
        Self {
            state: ParseState::Normal,
            buffer: Vec::new(),
        }
    }

    pub fn parse(&mut self, data: &[u8]) -> Vec<SequenceAction> {
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

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = ParseState::Normal;
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
