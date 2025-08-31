use std::path::PathBuf;

/// Get the directory for terminal replay files, checking TERM_REPLAY_DIR env var
pub fn get_term_replay_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TERM_REPLAY_DIR") {
        PathBuf::from(dir)
    } else {
        PathBuf::from("/tmp")
    }
}

/// Generate socket path for a given session name
pub fn get_socket_path(socket_name: &str) -> PathBuf {
    let mut path = get_term_replay_dir();
    path.push(format!("{}.sock", socket_name));
    path
}

/// Generate main log path for a given session name
pub fn get_log_path(socket_name: &str) -> PathBuf {
    let mut path = get_term_replay_dir();
    path.push(format!("{}.log", socket_name));
    path
}

/// Generate debug raw log path for a given session name
pub fn get_debug_raw_log_path(socket_name: &str) -> PathBuf {
    let mut path = get_term_replay_dir();
    path.push(format!("{}-raw.log", socket_name));
    path
}

/// Generate input log path for a given session name
pub fn get_input_log_path(socket_name: &str) -> PathBuf {
    let mut path = get_term_replay_dir();
    path.push(format!("{}-input.log", socket_name));
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_generation_with_default_dir() {
        // Test with default directory (/tmp)
        unsafe {
            std::env::remove_var("TERM_REPLAY_DIR");
        }

        let socket_path = get_socket_path("test-session");
        let log_path = get_log_path("test-session");
        let debug_path = get_debug_raw_log_path("test-session");
        let input_path = get_input_log_path("test-session");

        assert_eq!(socket_path, PathBuf::from("/tmp/test-session.sock"));
        assert_eq!(log_path, PathBuf::from("/tmp/test-session.log"));
        assert_eq!(debug_path, PathBuf::from("/tmp/test-session-raw.log"));
        assert_eq!(input_path, PathBuf::from("/tmp/test-session-input.log"));
    }

    #[test]
    fn test_path_generation_with_custom_dir() {
        // Test with custom directory via environment variable
        unsafe {
            std::env::set_var("TERM_REPLAY_DIR", "/var/run/user/1000");
        }

        let socket_path = get_socket_path("mysession");
        let log_path = get_log_path("mysession");
        let debug_path = get_debug_raw_log_path("mysession");
        let input_path = get_input_log_path("mysession");

        assert_eq!(
            socket_path,
            PathBuf::from("/var/run/user/1000/mysession.sock")
        );
        assert_eq!(log_path, PathBuf::from("/var/run/user/1000/mysession.log"));
        assert_eq!(
            debug_path,
            PathBuf::from("/var/run/user/1000/mysession-raw.log")
        );
        assert_eq!(
            input_path,
            PathBuf::from("/var/run/user/1000/mysession-input.log")
        );

        // Clean up
        unsafe {
            std::env::remove_var("TERM_REPLAY_DIR");
        }
    }
}