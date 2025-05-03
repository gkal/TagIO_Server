# TagIO HTTP Tunnel Server

## Overview

The TagIO HTTP Tunnel Server provides both HTTP tunneling and WebSocket capabilities for TagIO protocol clients, facilitating communication between clients behind firewalls or NAT devices. This server acts as a bridge for the TagIO protocol (a custom binary protocol for efficient device communication).

## Current Version: 0.3.0

Recent enhancements:
- Improved code organization and reduced complexity through refactoring
- Enhanced WebSocket handling with better error management
- Added helper functions to reduce code duplication
- Fixed naming conflicts in the build process
- Streamlined status page HTML

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
- Magic bytes: "TAGIO"
- Protocol version: 4 bytes (default: 0.0.0.1)
- Message type: ASCII (e.g., "PING", "ACK", "MSG")
- Client ID: 4-byte unique identifier
- Optional payload data

The server automatically assigns TagIO IDs in the range 5000-9999 to connected clients.

## License

All rights reserved. TagIO Team © 2025. 