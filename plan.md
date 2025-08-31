# Term-Tunnel Architecture Transformation Plan

## System Architecture Overview

### Existing System (Preserved Unchanged)
- `term-replay server [-S name] [command]` → creates `/tmp/{name}.sock` (default: term-replay)
- `term-replay client [-S name]` → connects directly to local `/tmp/{name}.sock`
- All current functionality preserved for backward compatibility

### New Tunnel System (Parallel Addition)  
- `term-tunnel [-S name] [command]` → creates `/tmp/{name}.sock` (default: term-tunnel)
- `term tunnel attach [-S name]` → WebSocket through tunnel to remote sessions
- `term tunnel list [-S name]` → HTTP through tunnel to list remote sessions
- Remote end runs `term-tunnel-server` to establish tunnel and serve HTTP/WebSocket

### Future Hybrid (Backlog)
- `term-replay client` could fallback: try local socket first, then tunnel socket
- Makes local/remote transparent to users

## Phase 1: Crate Reorganization
### 1.1 Create workspace structure
- Convert to Cargo workspace with multiple crates
- Main crates:
  - `term-core`: Core PTY/terminal management (extracted from current code)
  - `term-session`: Session management logic (extracted from current code)
  - `term-replay`: Current server/client binary (refactored to use crates)
  - `term-tunnel`: New tunnel client binary  
  - `term-tunnel-server`: New tunnel server binary
  - `term-protocol`: Shared protocol definitions

### 1.2 Refactor existing code
- Extract PTY logic to `term-core` (from current main.rs)
- Extract session management to `term-session` (from current main.rs)
- Refactor `term-replay` main.rs to use extracted crates
- Preserve all existing CLI and functionality exactly

## Phase 2: Tunnel Foundation
### 2.1 Command interface (same logic as existing server)
- `term-tunnel` → `bash -l` (login shell, same as server default)
- `term-tunnel bash` → `bash -c "bash"`
- `term-tunnel ssh@server` → `bash -c "ssh@server"`
- `term-tunnel "complex command"` → `bash -c "complex command"`
- Socket naming: `term-tunnel` → `/tmp/term-tunnel.sock`, `term-tunnel -S name` → `/tmp/name.sock`

### 2.2 Handshake protocol
- Spawned command runs normally until `term-tunnel-server` starts
- Server emits handshake sequence: `\x1b]tunnel-ready;\x07`
- Client detects handshake and switches to tunnel/smux mode
- Before handshake: normal terminal passthrough

## Phase 3: HTTP/WebSocket Server (term-tunnel-server)
### 3.1 Add dependencies
- axum for HTTP server
- tokio-tungstenite for WebSocket  
- smux for multiplexing

### 3.2 Session management integration
- Uses existing session logic from `term-session` crate
- `TERM_REPLAY_DIR` defaults to `/tmp/term-tunnel/` (mode 0700) if not set
- Sessions created on-demand when WebSocket connects (like current server)

### 3.3 Implement endpoints
- `/list-sessions`: HTTP GET, returns `ls *.sock` from `TERM_REPLAY_DIR`
- `/ws/attach/{session_id}`: WebSocket, spawns session like current server
- No `/input` or `/attach-session` - replaced by WebSocket bidirectional

## Phase 4: Tunnel Implementation
### 4.1 Client side (`term-tunnel`)
- Create Unix socket at `/tmp/{name}.sock` (default: term-tunnel)
- Spawn command using existing server logic
- Detect handshake sequence in output stream
- Switch to smux multiplexing after handshake
- Proxy Unix socket connections as smux streams

### 4.2 Server side (`term-tunnel-server`)
- Emit handshake sequence on startup
- Start HTTP/WebSocket server on localhost
- Accept smux connections from stdin/stdout
- Bridge smux streams to HTTP server
- Handle multiple concurrent connections

## Phase 5: Commands & Testing  
### 5.1 Implement tunnel commands
- `term tunnel attach [-S name]` → WebSocket to `/ws/attach/term-replay` (default session)
- `term tunnel list [-S name]` → HTTP GET to `/list-sessions`
- Use same socket resolution logic as existing client

### 5.2 Testing approach
- Use wscat for WebSocket testing: `wscat -c ws+unix:///tmp/term-tunnel.sock:/ws/attach/session1`
- Use socat for HTTP: `socat - UNIX-CONNECT:/tmp/term-tunnel.sock <<< "GET /list-sessions HTTP/1.1\r\n\r\n"`
- Integration tests for full tunnel flow

## Backlog Tickets

### Epic 1: Crate Reorganization (Foundation)
- [ ] TERM-001: Create Cargo workspace structure
- [ ] TERM-002: Extract term-core crate with PTY/terminal logic
- [ ] TERM-003: Extract term-session crate with session management
- [ ] TERM-004: Create term-protocol crate for shared types
- [ ] TERM-005: Refactor term-replay binary to use extracted crates
- [ ] TERM-006: Ensure all existing term-replay functionality preserved

### Epic 2: Tunnel Foundation (New Binaries)
- [ ] TERM-007: Create term-tunnel binary with command parsing
- [ ] TERM-008: Implement spawn logic (reuse server command logic)
- [ ] TERM-009: Add handshake detection in output stream
- [ ] TERM-010: Create term-tunnel-server binary skeleton
- [ ] TERM-011: Implement handshake emission on server startup

### Epic 3: HTTP/WebSocket Server (term-tunnel-server)
- [ ] TERM-012: Add axum, tokio-tungstenite, smux dependencies
- [ ] TERM-013: Implement /list-sessions endpoint (ls *.sock)
- [ ] TERM-014: Implement /ws/attach/{session} WebSocket endpoint
- [ ] TERM-015: Integrate with term-session for session spawning
- [ ] TERM-016: WebSocket to PTY bidirectional bridging

### Epic 4: Tunnel Transport (smux Integration)
- [ ] TERM-017: Client-side smux multiplexing after handshake
- [ ] TERM-018: Server-side smux demultiplexing to HTTP server
- [ ] TERM-019: Unix socket proxy to smux streams
- [ ] TERM-020: Handle connection cleanup and errors

### Epic 5: Commands & Testing
- [ ] TERM-021: Implement 'term tunnel attach' command
- [ ] TERM-022: Implement 'term tunnel list' command  
- [ ] TERM-023: Add -S naming support to tunnel commands
- [ ] TERM-024: Integration testing with wscat/socat
- [ ] TERM-025: End-to-end tunnel flow testing

### Epic 6: Polish & Future (Backlog)
- [ ] TERM-026: term-replay client fallback to tunnel socket
- [ ] TERM-027: Improved error messages and logging
- [ ] TERM-028: Performance optimization and flow control
- [ ] TERM-029: Security considerations and authentication
- [ ] TERM-030: Documentation and usage examples

## Implementation Order
1. **Phase 1**: Crate reorganization - extract existing code cleanly
2. **Phase 2**: Tunnel foundation - basic command spawning and handshake
3. **Phase 3**: HTTP/WebSocket server - remote session management  
4. **Phase 4**: Tunnel transport - smux multiplexing integration
5. **Phase 5**: Commands - user-facing tunnel attach/list commands

Each phase will be committed separately with working functionality.