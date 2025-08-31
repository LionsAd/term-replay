use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

#[tokio::test]
async fn test_websocket_session_creation() {
    // Test that WebSocket endpoint creates term-replay server automatically
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    // Set TERM_REPLAY_DIR to our temp directory
    std::env::set_var("TERM_REPLAY_DIR", temp_path);

    let session_id = "test-websocket-spawn";
    let socket_path = std::path::Path::new(temp_path).join(format!("{}.sock", session_id));

    // Ensure socket doesn't exist initially
    assert!(!socket_path.exists());

    // Test spawn logic (simplified - normally would be called by WebSocket handler)
    let spawn_result = term_tunnel_server::spawn_term_replay_server(session_id).await;
    assert!(spawn_result.is_ok());

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify socket was created
    assert!(socket_path.exists());

    // Clean up environment
    std::env::remove_var("TERM_REPLAY_DIR");
}

#[tokio::test]
async fn test_list_sessions_endpoint() {
    // Test that /list-sessions returns proper JSON format
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    // Create mock session sockets
    let session1_path = std::path::Path::new(temp_path).join("session1.sock");
    let session2_path = std::path::Path::new(temp_path).join("session2.sock");

    // Create Unix sockets (bind and immediately close to create file)
    let _listener1 = UnixListener::bind(&session1_path).unwrap();
    let _listener2 = UnixListener::bind(&session2_path).unwrap();

    // Set environment
    std::env::set_var("TERM_REPLAY_DIR", temp_path);

    // Test list sessions logic
    let sessions = term_tunnel_server::list_sessions().await.unwrap();

    // Should find both sessions
    assert_eq!(sessions.len(), 2);

    // Verify session format
    let session_names: Vec<&str> = sessions
        .iter()
        .filter_map(|s| s.get("id").and_then(|v| v.as_str()))
        .collect();

    assert!(session_names.contains(&"session1"));
    assert!(session_names.contains(&"session2"));

    // Clean up
    std::env::remove_var("TERM_REPLAY_DIR");
}

#[tokio::test]
async fn test_websocket_to_unix_bridge() {
    // Test bidirectional data flow between WebSocket and Unix socket
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    let session_id = "test-bridge";
    let socket_path = std::path::Path::new(temp_path).join(format!("{}.sock", session_id));

    // Create mock term-replay server
    let listener = UnixListener::bind(&socket_path).unwrap();
    let echo_server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Echo server - read and write back
            let mut buffer = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
                let _ = stream.write_all(&buffer[..n]).await;
            }
        }
    });

    // Set environment
    std::env::set_var("TERM_REPLAY_DIR", temp_path);

    // Create mock WebSocket (using Unix streams for testing)
    let (ws_client, mut ws_server) = UnixStream::pair().unwrap();

    // Start bridge in background
    let bridge_handle = tokio::spawn(async move {
        // Simulate the WebSocket bridge logic
        let mut unix_stream = UnixStream::connect(&socket_path).await.unwrap();

        let (mut ws_read, mut ws_write) = ws_server.split();
        let (mut unix_read, mut unix_write) = unix_stream.split();

        tokio::select! {
            _ = tokio::io::copy(&mut ws_read, &mut unix_write) => {},
            _ = tokio::io::copy(&mut unix_read, &mut ws_write) => {},
        }
    });

    // Give bridge time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test data flow
    let mut client = ws_client;
    let test_data = b"hello bridge test";
    client.write_all(test_data).await.unwrap();

    // Read echoed response
    let mut response = [0u8; 1024];
    let n = timeout(Duration::from_secs(1), client.read(&mut response))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&response[..n], test_data);

    // Cleanup
    bridge_handle.abort();
    echo_server.abort();
    std::env::remove_var("TERM_REPLAY_DIR");
}

#[tokio::test]
async fn test_session_wait_for_socket() {
    // Test waiting for socket to appear after spawning server
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();
    let session_id = "test-wait";
    let socket_path = std::path::Path::new(temp_path).join(format!("{}.sock", session_id));

    // Ensure socket doesn't exist
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).unwrap();
    }

    // Start waiting for socket in background
    let socket_path_clone = socket_path.clone();
    let wait_handle =
        tokio::spawn(async move { term_tunnel_server::wait_for_socket(&socket_path_clone).await });

    // Create socket after a delay
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _listener = UnixListener::bind(&socket_path).unwrap();
    });

    // Should complete successfully when socket appears
    let result = timeout(Duration::from_secs(2), wait_handle).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}
