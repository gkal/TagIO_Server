# TagIO HTTP Tunnel Server

## Overview

The TagIO HTTP Tunnel Server provides both HTTP tunneling and WebSocket capabilities for TagIO protocol clients, facilitating communication between clients behind firewalls or NAT devices. This server acts as a bridge for the TagIO protocol (a custom binary protocol for efficient device communication).

## Current Version: 0.3.2

Recent enhancements:
- Fixed ACK message format to ensure correct binary structure
- Added REGL/REGLACK protocol for client ID confirmation
- Implemented error handling with REGLERR responses
- Updated to big-endian format for all numeric identifiers
- Added detailed binary protocol documentation with WebSocket framing
- Improved debug logging for binary message tracing

## Project Structure

### Key Files

| File | Description |
|------|-------------|
| `standalone_server/src/bin/http_tunnel_server.rs` | Main executable implementing the HTTP Tunnel Server |
| `src/lib.rs` | Placeholder library file for the workspace |
| `src/debug_logging.rs` | Utilities for debug logging |
| `standalone_server/Cargo.toml` | Manifest file for the standalone server |
| `Cargo.toml` | Root workspace manifest file |

### Components

The HTTP Tunnel Server handles:
1. **HTTP Tunneling**: Clients can send TagIO protocol messages via HTTP POST requests
2. **WebSocket Support**: Real-time bidirectional communication for TagIO clients
3. **Client Registry**: Tracks connected clients with unique TagIO IDs
4. **Protocol Handling**: Processes TagIO protocol messages and generates appropriate responses

## Features

- **WebSocket Support**: Efficient real-time communication
- **HTTP Fallback**: Support for clients that can't use WebSockets
- **Status Page**: Web interface showing server status
- **Protocol Detection**: Automatic detection of TagIO protocol in requests
- **Client Tracking**: Registry of connected clients with cleanup of stale connections
- **Comprehensive Logging**: Detailed logging for operations and debugging

## Building and Running

### Building the Server

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release
```

### Running the Server

```bash
# Run with default settings
./target/release/http_tunnel_server

# Run with custom port and log level
./target/release/http_tunnel_server --port 8080 --log-level debug

# Run with log file
./target/release/http_tunnel_server --log-file server.log
```

## Command Line Options

- `--port, -p`: Port to bind to (default: 10000 or from PORT environment variable)
- `--log-level, -l`: Log level (trace, debug, info, warn, error)
- `--log-file`: Optional file to write logs to
- `--use-tls`: Enable HTTPS/TLS support (experimental)
- `--cert-file`: Path to TLS certificate file (for HTTPS)
- `--key-file`: Path to TLS private key file (for HTTPS)

## Cloud Deployment

The server is designed to be easily deployed to cloud platforms like Render.com:

1. Connect your GitHub repository to Render
2. Build command: `cargo build --release`
3. Start command: `./target/release/http_tunnel_server`
4. The server automatically uses the `PORT` environment variable provided by Render

## TagIO Protocol

The TagIO protocol uses:
- Magic bytes: "TAGIO" (ASCII: 54 41 47 49 4F)
- Protocol version: 4 bytes (default: 00 00 00 01)
- Message type: ASCII (e.g., "PING", "ACK", "MSG")
- Client ID: 4-byte unique identifier in **big-endian** format
- Optional payload data

The server automatically assigns TagIO IDs in the range 5000-9999 to connected clients.

### WebSocket Framing

When sent over WebSockets, TagIO messages are wrapped in WebSocket binary frames:

#### Example ACK Message with WebSocket Frame
0x82 0x10: WebSocket binary frame header (indicates binary data, 16 bytes)
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
41 43 4B: "ACK" Message type
00 00 18 4B: TagIO ID 6219 in big-endian format

### Protocol Message Types

1. **PING** (Client to Server)
0x82 0x0D: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
50 49 4E 47: "PING" Message type

2. **ACK** (Server to Client)
0x82 0x10: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
41 43 4B: "ACK" Message type
XX XX XX XX: TagIO ID in big-endian format

3. **REGL** (Client to Server)
0x82 0xXX: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
52 45 47 4C: "REGL" Message type
52 45 47 49 53 54 45 52 3A XXXX: "REGISTER:XXXX" (ID as string)

4. **REGLACK** (Server to Client)
0x82 0x10: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
52 45 47 4C 41 43 4B: "REGLACK" Message type

5. **REGLERR** (Server to Client on Error)
0x82 0xXX: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
52 45 47 4C 45 52 52: "REGLERR" Message type
XX XX...: Error message as ASCII bytes (Examples: ID_MISMATCH, INVALID_ID, MISSING_ID)

6. **MSG** (Bidirectional)
0x82 0xXX: WebSocket frame header
54 41 47 49 4F: "TAGIO" Magic bytes
00 00 00 01: Protocol version
4D 53 47: "MSG" Message type
XX XX XX XX: Target ID in big-endian format
XX XX...: Optional payload data

### Endianness Note

**IMPORTANT:** As of version 0.3.2, all numeric identifiers in the TagIO protocol are encoded in **big-endian** format. Previous versions used little-endian encoding, which could cause data corruption when clients and servers had different expectations.

## WebSocket Implementation

When using WebSockets with TagIO:

1. All protocol messages must be sent as binary WebSocket frames (opcode 0x02)
2. The server validates WebSocket connections by checking for proper upgrade headers
3. Clients must use proper WebSocket framing and masking
4. Binary frames containing TagIO protocol data are automatically parsed and processed
5. The server supports WebSocket ping/pong frames for keepalive connections
6. Inactive WebSocket connections are cleaned up after 1 hour of inactivity

## License

All rights reserved. TagIO Team © 2025. 