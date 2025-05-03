# TagIO HTTP Tunnel Server

## Overview

The TagIO HTTP Tunnel Server provides both HTTP tunneling and WebSocket capabilities for TagIO protocol clients, facilitating communication between clients behind firewalls or NAT devices. This server acts as a bridge for the TagIO protocol (a custom binary protocol for efficient device communication).

## Current Version: 0.3.1

Recent enhancements:
- Improved code organization and reduced complexity through refactoring
- Enhanced WebSocket handling with better error management
- Added helper functions to reduce code duplication
- Fixed naming conflicts in the build process
- Streamlined status page HTML
- Updated log format for better readability

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

### Protocol Message Formats

1. **ACK Response** (server → client):
   ```
   TAGIO + [Version: 00 00 00 01] + "ACK" + [Client ID: 4 bytes, big-endian]
   ```
   Example: `54 41 47 49 4F 00 00 00 01 41 43 4B 00 00 19 FB` (ID: 6651)

2. **PING Message** (client → server):
   ```
   TAGIO + [Version: 00 00 00 01] + "PING"
   ```
   Example: `54 41 47 49 4F 00 00 00 01 50 49 4E 47`

3. **REGL Message** (client → server):
   ```
   TAGIO + [Version: 00 00 00 01] + "REGL" + "REGISTER:<assigned_id>"
   ```
   Example: `54 41 47 49 4F 00 00 00 01 52 45 47 4C 52 45 47 49 53 54 45 52 3A 37 38 39 30`

4. **REGLACK Message** (server → client):
   ```
   TAGIO + [Version: 00 00 00 01] + "REGLACK"
   ```
   Example: `54 41 47 49 4F 00 00 00 01 52 45 47 4C 41 43 4B`

5. **REGLERR Message** (server → client on error):
   ```
   TAGIO + [Version: 00 00 00 01] + "REGLERR" + [Error message]
   ```
   Error types: `ID_MISMATCH`, `INVALID_ID`, `MISSING_ID`, `MISSING_REGISTER`, `INVALID_FORMAT`
   
   Example: `54 41 47 49 4F 00 00 00 01 52 45 47 4C 45 52 52 49 44 5F 4D 49 53 4D 41 54 43 48` (ID_MISMATCH)

6. **MSG Message** (bidirectional):
   ```
   TAGIO + [Version: 00 00 00 01] + "MSG" + [Target ID: 4 bytes, big-endian] + [Payload]
   ```

7. **REGISTER Message** (client → server):
   ```
   TAGIO + [Version: 00 00 00 01] + "REGISTER" + [Client ID: 4 bytes, big-endian]
   ```

8. **REG_ACK Message** (server → client):
   ```
   TAGIO + [Version: 00 00 00 01] + "REG_ACK"
   ```

### Endianness Note

**IMPORTANT:** As of version 0.3.1, all numeric identifiers in the TagIO protocol are encoded in **big-endian** format. Previous versions used little-endian encoding, which could cause data corruption when clients and servers had different expectations.

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