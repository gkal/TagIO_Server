# TagIO HTTP Tunnel Server

This is the HTTP tunnel server for TagIO, providing a simple and efficient way to tunnel the TagIO protocol over HTTP and WebSocket connections.

## Project Structure

The project has been reorganized for better maintainability:

- `src/lib.rs` - Main library that exports all modules
- `src/bin/http_tunnel_server.rs` - Main executable entry point
- `src/client.rs` - Client management and tracking
- `src/http.rs` - HTTP protocol handling
- `src/logger.rs` - Logging setup
- `src/protocol.rs` - TagIO protocol implementation
- `src/websocket.rs` - WebSocket handling

## Building

```bash
# Build in release mode
cargo build --release

# Run the server
./target/release/http_tunnel_server

# Or with custom port
./target/release/http_tunnel_server --port 8080

# Or with TLS enabled
./target/release/http_tunnel_server --use-tls --cert-file cert.pem --key-file key.pem
```

## Command Line Options

```
Usage: http_tunnel_server [OPTIONS]

Options:
  -p, --port <PORT>          Port to bind to [default: 10000]
  -l, --log-level <LOG_LEVEL>  Log level [default: info]
      --log-file <LOG_FILE>  Log to file
      --use-tls              Enable HTTPS/TLS support
      --cert-file <CERT_FILE>  Path to TLS certificate file
      --key-file <KEY_FILE>  Path to TLS private key file
  -h, --help                 Print help
  -V, --version              Print version
```

## Protocol Support

The server supports the TagIO protocol over both HTTP POST requests and WebSocket connections. See the [TagIO protocol specification](docs/protocol.md) for details.

## Features

- HTTP tunneling for TagIO protocol
- WebSocket connection support
- Client tracking and management
- Proper ACK messaging for reliable communication
- REGL/REGLACK support for client registration

## Development

The server uses Rust with the following key dependencies:
- tokio for async runtime
- hyper for HTTP server
- hyper-tungstenite for WebSocket
- clap for command line parsing
- fern/log for logging

All binaries are built in the `target/release` directory. 