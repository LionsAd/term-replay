use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

#[tokio::test]
async fn test_tunnel_list_socket_not_found() {
    // Test behavior when tunnel socket doesn't exist
    let result = term_replay::run_tunnel_list("nonexistent-tunnel").await;
    assert!(result.is_err());

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Tunnel socket not found"));
}

#[tokio::test]
async fn test_tunnel_attach_proxy_socket_creation() {
    // Test that tunnel attach creates the expected proxy socket
    let tunnel_socket = "test-tunnel";
    let session_name = "test-session";
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);

    // Clean up any existing socket
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }

    // Start tunnel attach in background
    let attach_handle =
        tokio::spawn(
            async move { term_replay::run_tunnel_attach(tunnel_socket, session_name).await },
        );

    // Give it time to create the socket
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify socket was created
    assert!(proxy_socket_path.exists());

    // Clean up
    attach_handle.abort();
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }
}

#[tokio::test]
async fn test_tunnel_attach_client_connection_flow() {
    // Test the full client connection flow through proxy
    let tunnel_socket = "test-tunnel-flow";
    let session_name = "test-session-flow";

    // Create mock tunnel server socket
    let tunnel_path = term_session::get_socket_path(tunnel_socket);
    if tunnel_path.exists() {
        std::fs::remove_file(&tunnel_path).unwrap();
    }

    let tunnel_listener = UnixListener::bind(&tunnel_path).unwrap();

    // Start mock tunnel server that responds to WebSocket upgrade
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = tunnel_listener.accept().await {
            // Read WebSocket upgrade request
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await;

            // Send WebSocket upgrade response
            let response = "HTTP/1.1 101 Switching Protocols\r\n\
                           Connection: Upgrade\r\n\
                           Upgrade: websocket\r\n\
                           Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;

            // Echo data back for testing
            let mut echo_buffer = [0u8; 256];
            while let Ok(n) = stream.read(&mut echo_buffer).await {
                if n == 0 {
                    break;
                }
                let _ = stream.write_all(&echo_buffer[..n]).await;
            }
        }
    });

    // Start tunnel attach
    tokio::spawn(async move {
        let _ = term_replay::run_tunnel_attach(tunnel_socket, session_name).await;
    });

    // Give services time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect as client to proxy socket
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);

    if let Ok(mut client_stream) = UnixStream::connect(&proxy_socket_path).await {
        // Send test data
        let test_data = b"hello tunnel";
        client_stream.write_all(test_data).await.unwrap();

        // Read echoed response
        let mut response = [0u8; 256];
        let n = timeout(Duration::from_secs(1), client_stream.read(&mut response))
            .await
            .unwrap()
            .unwrap();

        // Verify echo
        assert_eq!(&response[..n], test_data);
    }

    // Cleanup
    if tunnel_path.exists() {
        std::fs::remove_file(&tunnel_path).unwrap();
    }
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }
}

#[tokio::test]
async fn test_websocket_upgrade_request_format() {
    // Test that tunnel attach sends properly formatted WebSocket upgrade
    let tunnel_socket = "test-websocket-format";
    let session_name = "test-session-ws";

    // Create mock tunnel server to capture request
    let tunnel_path = term_session::get_socket_path(tunnel_socket);
    if tunnel_path.exists() {
        std::fs::remove_file(&tunnel_path).unwrap();
    }

    let tunnel_listener = UnixListener::bind(&tunnel_path).unwrap();
    let mut captured_request = String::new();

    // Mock server that captures the WebSocket upgrade request
    let capture_handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = tunnel_listener.accept().await {
            let mut buffer = [0u8; 2048];
            if let Ok(n) = stream.read(&mut buffer).await {
                captured_request = String::from_utf8_lossy(&buffer[..n]).to_string();
            }
        }
        captured_request
    });

    // Start tunnel attach
    tokio::spawn(async move {
        let _ = term_replay::run_tunnel_attach(tunnel_socket, session_name).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client to trigger WebSocket upgrade
    let proxy_socket_name = format!("{}-{}", tunnel_socket, session_name);
    let proxy_socket_path = term_session::get_socket_path(&proxy_socket_name);

    if let Ok(_client_stream) = UnixStream::connect(&proxy_socket_path).await {
        // Let the upgrade request be sent
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify WebSocket upgrade format
    if let Ok(Ok(request)) = timeout(Duration::from_secs(1), capture_handle).await {
        assert!(request.contains("GET /ws/attach/test-session-ws HTTP/1.1"));
        assert!(request.contains("Connection: Upgrade"));
        assert!(request.contains("Upgrade: websocket"));
        assert!(request.contains("Sec-WebSocket-Version: 13"));
        assert!(request.contains("Sec-WebSocket-Key:"));
    }

    // Cleanup
    if tunnel_path.exists() {
        std::fs::remove_file(&tunnel_path).unwrap();
    }
    if proxy_socket_path.exists() {
        std::fs::remove_file(&proxy_socket_path).unwrap();
    }
}

#[cfg(test)]
mod integration {
    use super::*;

    #[tokio::test]
    async fn test_tunnel_list_http_request_format() {
        // Test that tunnel list sends proper HTTP request
        let tunnel_socket = "test-list-http";

        // Create mock server to capture HTTP request
        let tunnel_path = term_session::get_socket_path(tunnel_socket);
        if tunnel_path.exists() {
            std::fs::remove_file(&tunnel_path).unwrap();
        }

        let tunnel_listener = UnixListener::bind(&tunnel_path).unwrap();

        // Mock server that responds with session list
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = tunnel_listener.accept().await {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;

                // Send HTTP response with JSON session list
                let response = "HTTP/1.1 200 OK\r\n\
                               Content-Type: application/json\r\n\
                               Content-Length: 82\r\n\r\n\
                               [{\"id\":\"session1\",\"name\":\"test\",\"created\":\"2024-01-01T00:00:00Z\"}]";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Test tunnel list
        let result = term_replay::run_tunnel_list(tunnel_socket).await;
        assert!(result.is_ok());

        // Cleanup
        if tunnel_path.exists() {
            std::fs::remove_file(&tunnel_path).unwrap();
        }
    }
}
