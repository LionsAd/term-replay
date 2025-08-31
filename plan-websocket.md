# WebSocket Integration Plan - SIMPLIFIED

## Core Principle: Direct Bridge to term-replay

The WebSocket implementation acts as a **transparent bridge** between WebSocket clients and the existing `term-replay` server/client infrastructure. No new protocols, no smux complexity - just a clean pass-through.

## Architecture Overview

```
Browser/WebSocket Client
        ↓
    WebSocket
        ↓
term-tunnel-server (HTTP/WS server)
        ↓
    Unix Socket
        ↓
term-replay server (existing)
```

## Key Design Decisions

1. **NO new protocol** - WebSocket carries raw terminal data, exactly as term-replay client/server exchange it
2. **Reuse existing infrastructure** - term-replay server handles all PTY management, logging, session lifecycle
3. **On-demand session creation** - If session doesn't exist, spawn `term-replay server <session>` automatically
4. **Direct socket connection** - WebSocket handler connects to Unix socket, just like term-replay client does

## Implementation Plan

### Phase 1: WebSocket Endpoint Setup

#### 1.1 Add WebSocket Handler to term-tunnel-server
- Add `/ws/attach/{session_id}` endpoint to router
- WebSocket upgrade handling via axum's built-in support
- Session ID maps directly to socket name

#### 1.2 Session Path Resolution
```rust
// Example: /ws/attach/claude → /tmp/term-tunnel/claude.sock
// Or if TERM_REPLAY_DIR=/custom/dir → /custom/dir/claude.sock
let socket_path = get_socket_path(&session_id);
```

### Phase 2: Auto-spawn term-replay Server

#### 2.1 Check and Create Session
```rust
if !socket_path.exists() {
    // Spawn: term-replay server <session_id>
    Command::new("term-replay")
        .arg("server")
        .arg(&session_id)
        .spawn()?;
    
    // Wait for socket to appear (with timeout)
    wait_for_socket(&socket_path).await?;
}
```

#### 2.2 Connect to Unix Socket
```rust
// Connect exactly like term-replay client does
let stream = UnixStream::connect(&socket_path).await?;
```

### Phase 3: Bidirectional Bridge

#### 3.1 WebSocket ↔ Unix Socket Relay
```rust
// Simple bidirectional copy
// WebSocket → Unix Socket (browser input → PTY)
// Unix Socket → WebSocket (PTY output → browser)
tokio::select! {
    // Forward WebSocket data to Unix socket
    Some(msg) = ws_rx.recv() => {
        unix_writer.write_all(&msg.into_bytes()).await?;
    }
    // Forward Unix socket data to WebSocket
    Ok(n) = unix_reader.read(&mut buffer) => {
        ws_tx.send(Message::Binary(buffer[..n].to_vec())).await?;
    }
}
```

#### 3.2 Handle Resize Events
- WebSocket receives resize messages: `\x1b[8;<rows>;<cols>t`
- Forward directly to Unix socket (term-replay server handles it)

#### 3.3 Connection Cleanup
- On WebSocket disconnect: close Unix socket connection
- term-replay server continues running (allows reconnection)
- Session persists until term-replay server is stopped

### Phase 4: `/list-sessions` Implementation

#### 4.1 List Available Sessions
```rust
// Read directory where sockets are stored
let dir = get_term_replay_dir();
let entries = fs::read_dir(dir)?;

// Filter for .sock files
let sessions: Vec<String> = entries
    .filter_map(|entry| {
        let path = entry.ok()?.path();
        if path.extension()? == "sock" {
            Some(path.file_stem()?.to_string())
        } else {
            None
        }
    })
    .collect();
```

### Phase 5: Integration with term-tunnel

#### 5.1 Update term-tunnel Mode Switch
- After handshake detection, term-tunnel-server is running
- HTTP/WebSocket server is accessible via tunnel
- Browser can connect to `/ws/attach/<session>`

#### 5.2 Unix Socket Creation in term-tunnel
- Create Unix socket at `/tmp/term-tunnel.sock` 
- Accept connections and forward through smux to term-tunnel-server
- This enables: `Browser → tunnel → term-tunnel-server → term-replay server`

## Testing Strategy

### Manual Testing
```bash
# 1. Start tunnel
term-tunnel ./target/debug/term-tunnel-server

# 2. Test WebSocket with wscat
wscat -c ws://localhost:8080/ws/attach/test-session

# 3. Verify term-replay server auto-spawned
ls /tmp/test-session.sock

# 4. Type in wscat, see output
# 5. Open another wscat to same session - verify shared
```

### Integration Tests
1. Test auto-spawn of term-replay server
2. Test WebSocket data forwarding
3. Test resize handling
4. Test session listing
5. Test reconnection to existing session

## File Changes Required

### 1. `crates/term-tunnel-server/Cargo.toml`
- Already has `axum` with `ws` feature ✓
- Add `term-session` dependency for path utilities
- Add `term-server` dependency (optional, for embedded spawning)

### 2. `crates/term-tunnel-server/src/main.rs`
- Add WebSocket handler function
- Add session auto-spawn logic
- Implement bidirectional bridge
- Update `/list-sessions` to read actual socket files

### 3. `crates/term-tunnel/src/main.rs`
- After tunnel mode activation, create Unix socket listener
- Accept connections and forward through smux

## Benefits of This Approach

1. **Simplicity**: No new protocols or complex state management
2. **Reusability**: Leverages all existing term-replay functionality
3. **Compatibility**: Works with existing term-replay clients
4. **Maintainability**: Minimal code changes, clear separation of concerns
5. **Reliability**: term-replay server is already battle-tested

## Success Criteria

- [ ] WebSocket connects to `/ws/attach/session-name`
- [ ] Auto-spawns term-replay server if needed
- [ ] Bidirectional terminal I/O works
- [ ] Multiple clients can connect to same session
- [ ] `/list-sessions` shows actual .sock files
- [ ] Clean disconnection and reconnection
- [ ] Works through tunnel (smux forwarding)

## Timeline

- **Day 1**: WebSocket endpoint and Unix socket connection
- **Day 2**: Auto-spawn logic and bidirectional bridge
- **Day 3**: Session listing and tunnel integration
- **Day 4**: Testing and bug fixes