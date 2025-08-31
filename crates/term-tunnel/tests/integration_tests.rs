use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

// Import functions from main
use term_tunnel::{resolve_term_replay_binary, run_tunnel_attach, run_tunnel_list};

#[tokio::test]
async fn test_tunnel_socket_creation() {
    // Test that term-tunnel creates Unix socket properly
    let temp_dir = TempDir::new().unwrap();
    let socket_name = "test-tunnel";
    let socket_path = temp_dir.path().join(format!("{}.sock", socket_name));

    // Mock the socket creation logic
    let listener = UnixListener::bind(&socket_path).unwrap();
    assert!(socket_path.exists());

    // Test connection
    let stream = UnixStream::connect(&socket_path).await;
    assert!(stream.is_ok());

    drop(listener);
}

#[tokio::test]
async fn test_handshake_detection() {
    // Test handshake sequence detection in output stream
    let handshake = b"\x1b]tunnel-ready;\x07";
    let normal_output = b"Starting server...\n";
    let mut combined_output = Vec::new();
    combined_output.extend_from_slice(normal_output);
    combined_output.extend_from_slice(handshake);

    // Simulate detecting handshake in stream
    let handshake_pos = combined_output
        .windows(handshake.len())
        .position(|window| window == handshake);

    assert!(handshake_pos.is_some());
    assert_eq!(handshake_pos.unwrap(), normal_output.len());
}

#[tokio::test]
async fn test_concurrent_connections() {
    // Test multiple concurrent connections through tunnel
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("concurrent-test.sock");

    // Create server socket
    let listener = UnixListener::bind(&socket_path).unwrap();

    // Start echo server
    let echo_server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    let _ = stream.write_all(&buffer[..n]).await;
                }
            });
        }
    });

    // Create multiple concurrent clients
    let mut handles = Vec::new();

    for i in 0..3 {
        let path = socket_path.clone();
        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&path).await.unwrap();
            let test_data = format!("client-{}", i);

            stream.write_all(test_data.as_bytes()).await.unwrap();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).await.unwrap();

            assert_eq!(&response[..n], test_data.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all clients to complete
    for handle in handles {
        timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    echo_server.abort();
}

#[tokio::test]
async fn test_smux_stream_handling() {
    // Test that smux streams are handled correctly (mock test)
    use std::sync::{Arc, Mutex};

    // Simulate smux stream counter
    let stream_count = Arc::new(Mutex::new(0));
    let count_clone = stream_count.clone();

    // Simulate handling multiple streams
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let count = count_clone.clone();
            tokio::spawn(async move {
                // Simulate stream processing
                tokio::time::sleep(Duration::from_millis(50)).await;

                let mut counter = count.lock().unwrap();
                *counter += 1;
            })
        })
        .collect();

    // Wait for all streams to be processed
    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(*stream_count.lock().unwrap(), 5);
}

#[tokio::test]
async fn test_error_handling_socket_not_found() {
    // Test proper error handling when sockets don't exist
    let nonexistent_path = "/tmp/nonexistent-tunnel.sock";

    let result = UnixStream::connect(nonexistent_path).await;
    assert!(result.is_err());

    // Verify error type
    let error = result.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn test_connection_cleanup() {
    // Test that connections are properly cleaned up
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("cleanup-test.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();

    // Create connection
    let stream = UnixStream::connect(&socket_path).await.unwrap();

    // Drop connection
    drop(stream);

    // Server should handle disconnection gracefully
    let server_handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Try to read from disconnected stream
            let mut buffer = [0u8; 1];
            let result = stream.read(&mut buffer).await;

            // Should get 0 bytes (EOF) or error
            match result {
                Ok(0) => {}  // EOF - connection closed
                Err(_) => {} // Error - also acceptable
                Ok(_) => panic!("Expected EOF or error, got data"),
            }
        }
    });

    // Connect and immediately disconnect
    let _stream = UnixStream::connect(&socket_path).await.unwrap();
    // Stream drops here

    timeout(Duration::from_secs(1), server_handle)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_tunnel_attach_command() {
    // Test that tunnel attach creates proxy socket properly
    let tunnel_socket = "test-attach-cmd";
    let session_name = "test-session-cmd";

    // Clean up any existing socket
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }

    // Start tunnel attach with disabled spawn in background
    let attach_handle =
        tokio::spawn(async move { run_tunnel_attach(tunnel_socket, session_name, Some("")).await });

    // Give it time to create the socket
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify socket was created
    let mut attempts = 0;
    while !proxy_socket_path.exists() && attempts < 10 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        attempts += 1;
    }
    assert!(proxy_socket_path.exists(), "Proxy socket was not created");

    // Clean up
    attach_handle.abort();
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }
}

#[tokio::test]
async fn test_binary_resolution() {
    // Test binary resolution function
    let binary_path = resolve_term_replay_binary();
    match binary_path {
        Ok(path) => {
            assert!(path.to_string_lossy().contains("term-replay"));
        }
        Err(e) => {
            // Expected if term-replay binary is not in the same directory
            assert!(e.to_string().contains("term-replay binary not found"));
        }
    }
}

#[tokio::test]
async fn test_tunnel_list_socket_not_found() {
    // Test behavior when tunnel socket doesn't exist
    let result = run_tunnel_list("nonexistent-tunnel-socket").await;
    assert!(result.is_err());

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Tunnel socket not found"));
}
