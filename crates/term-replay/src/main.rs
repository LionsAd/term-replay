use anyhow::Result;
use clap::{Parser, Subcommand};

// Import from our extracted crates
use term_client::run_client;
use term_protocol::parse_detach_char;
use term_server::run_server;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the persistent terminal server
    Server {
        /// Set the socket name (default: term-replay). Creates {name}.sock and {name}.log
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
        /// Custom command to run instead of bash (default: ["bash"])
        #[arg(value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Attach to the persistent terminal server
    Client {
        /// Set the detach character (default: Ctrl-\). Use '^?' for DEL, '^X' for Ctrl-X
        #[arg(short = 'e', long = "escape", value_name = "CHAR")]
        detach_char: Option<String>,
        /// Set the socket name (default: term-replay). Connects to {name}.sock
        #[arg(short = 'S', long = "socket-name", value_name = "NAME")]
        socket_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging based on environment variables
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "error".to_string());

    tracing_subscriber::fmt().with_env_filter(log_level).init();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Server {
            socket_name,
            command,
        } => {
            let session_name = socket_name.unwrap_or_else(|| "term-replay".to_string());
            let cmd = if command.is_empty() {
                vec!["bash".to_string(), "-l".to_string()]
            } else {
                command
            };
            run_server(&session_name, &cmd).await
        }
        Commands::Client {
            detach_char,
            socket_name,
        } => {
            let detach_byte = if let Some(char_str) = detach_char {
                parse_detach_char(&char_str)?
            } else {
                0x1C // Default: Ctrl-\
            };
            let session_name = socket_name.unwrap_or_else(|| "term-replay".to_string());
            run_client(detach_byte, &session_name).await
        }
    };

    result
}
