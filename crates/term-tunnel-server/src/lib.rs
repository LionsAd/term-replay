use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

pub async fn spawn_term_replay_server(session_id: &str) -> Result<()> {
    let term_replay_dir =
        std::env::var("TERM_REPLAY_DIR").unwrap_or_else(|_| "/tmp/term-tunnel".to_string());

    // Ensure directory exists
    tokio::fs::create_dir_all(&term_replay_dir).await?;

    tracing::info!("🚀 Spawning term-replay server for session: {}", session_id);

    let mut cmd = Command::new("term-replay");
    cmd.arg("server")
        .arg("-S")
        .arg(session_id)
        .env("TERM_REPLAY_DIR", &term_replay_dir);

    cmd.spawn()?;

    Ok(())
}

pub async fn wait_for_socket(socket_path: &Path) -> Result<()> {
    let timeout_duration = Duration::from_secs(5);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout_duration {
        if socket_path.exists() {
            // Give a bit more time for the socket to be ready
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Timeout waiting for socket: {}", socket_path.display());
}

pub async fn list_sessions() -> Result<Vec<serde_json::Value>> {
    let term_replay_dir =
        std::env::var("TERM_REPLAY_DIR").unwrap_or_else(|_| "/tmp/term-tunnel".to_string());

    let mut sessions = Vec::new();
    let dir_path = Path::new(&term_replay_dir);

    if !dir_path.exists() {
        return Ok(sessions);
    }

    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name.ends_with(".sock") {
                let session_id = file_name.strip_suffix(".sock").unwrap_or(file_name);

                // Get creation time
                let metadata = entry.metadata().await?;
                let created = metadata
                    .created()
                    .or_else(|_| metadata.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                let created_str = chrono::DateTime::<chrono::Utc>::from(created)
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string();

                let session = serde_json::json!({
                    "id": session_id,
                    "name": session_id,
                    "created": created_str
                });

                sessions.push(session);
            }
        }
    }

    Ok(sessions)
}

/// Resolve the term-replay binary path from the same directory as the current executable
pub fn resolve_term_replay_binary() -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to get current executable path: {}", e))?;

    let current_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get parent directory of current executable"))?;

    let term_replay_path = current_dir.join("term-replay");

    // Check if the binary exists
    if !term_replay_path.exists() {
        anyhow::bail!(
            "term-replay binary not found at expected path: {}. Please ensure term-replay is in the same directory as term-tunnel-server.",
            term_replay_path.display()
        );
    }

    Ok(term_replay_path)
}

/// Spawn term-replay server with optional custom command
pub async fn spawn_term_replay_server_with_command(
    session_id: &str,
    custom_command: Option<&str>,
) -> Result<()> {
    let term_replay_dir =
        std::env::var("TERM_REPLAY_DIR").unwrap_or_else(|_| "/tmp/term-tunnel".to_string());

    // Ensure directory exists
    tokio::fs::create_dir_all(&term_replay_dir).await?;

    let command_path = match custom_command {
        Some("") => {
            // Empty string means disable auto-spawn
            return Ok(());
        }
        Some(cmd) => PathBuf::from(cmd),
        None => {
            // Default: use term-replay from same directory
            resolve_term_replay_binary()?
        }
    };

    tracing::info!(
        "🚀 Spawning server with command: {} server -S {}",
        command_path.display(),
        session_id
    );

    let mut cmd = Command::new(&command_path);
    cmd.arg("server")
        .arg("-S")
        .arg(session_id)
        .env("TERM_REPLAY_DIR", &term_replay_dir);

    cmd.spawn()?;

    Ok(())
}
