# TagIO HTTP Tunnel Server - Standalone Version

## Purpose

This standalone server provides HTTP tunneling and WebSocket capabilities for the TagIO protocol, enabling communication for clients behind firewalls or NAT devices.

## Current Version: 0.3.0

Recent improvements:
- Refactored for better code organization
- Enhanced WebSocket handling
- Improved error management
- Better protocol detection logic
- Reduced code duplication with helper functions

## Features

- **HTTP Tunneling**: Allows sending TagIO protocol messages via HTTP POST requests
- **WebSocket Support**: Enables real-time bidirectional communication
- **TagIO Protocol**: Full support for the custom binary TagIO protocol
- **Client Registry**: Tracks connected clients with unique IDs
- **Cloud-Ready**: Optimized for deployment on platforms like Render.com
- **Comprehensive Logging**: Detailed logging for operations and debugging

## Cloud Deployment

The server is designed to be deployed to `tagio-server.onrender.com` for production use.

### Deployment to Render.com

1. Create a new Web Service on Render.com
2. Connect your GitHub repository
3. Configure as:
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/http_tunnel_server`
   - The server automatically uses the `PORT` environment variable

## Running Locally

```bash
cargo run --release
```

Or with custom configuration:

```bash
cargo run --release -- --port 8080 --log-level debug
```

## Configuration Options

- `--port, -p`: Port to bind to (default: 10000)
- `--log-level, -l`: Log level (trace, debug, info, warn, error)
- `--log-file`: File to write logs to
- `--use-tls`: Enable HTTPS/TLS support (experimental)
- `--cert-file`: Path to TLS certificate file (for HTTPS)
- `--key-file`: Path to TLS private key file (for HTTPS)

## Protocol Details

This server implements the TagIO protocol with the following features:

- Magic bytes validation ("TAGIO")
- Protocol version checking (4 bytes)
- Message type identification
- Client ID tracking (4-byte unique identifier)
- Bidirectional communication
- Automatic client registration

TagIO clients are assigned unique IDs in the range 5000-9999.

## Building from Source

```bash
cargo build --release
```

The executable will be available at `target/release/http_tunnel_server`.

## License

All rights reserved. TagIO Team © 2025. 