# TagIO Relay Server

A standalone relay server for TagIO remote desktop application, providing NAT traversal and relay capabilities.

## Overview

The TagIO relay server allows TagIO clients to establish peer-to-peer connections even when behind NAT or firewalls. This standalone version contains only the server functionality, with no dependencies on the client/GUI code.

## Features

- **NAT Traversal**: Helps clients establish direct peer-to-peer connections
- **Relay Capability**: Falls back to relaying data when direct connections aren't possible
- **Authentication**: Optional client authentication for secure deployments
- **Health Check Endpoint**: For monitoring server health

## Building

```bash
cargo build --release
```

This will create the executable in the `target/release` directory.

## Running

### Basic Usage

```bash
# Run with default settings (0.0.0.0:443)
target/release/tagio_relay_server

# Run with custom bind address
target/release/tagio_relay_server --bind 0.0.0.0:8443

# Run with explicit public IP (recommended for production)
target/release/tagio_relay_server --public-ip 123.45.67.89

# Run with authentication enabled
target/release/tagio_relay_server --auth your_secret_here

# Run with interactive setup
target/release/tagio_relay_server --interactive
```

### Command Line Options

- `--bind`, `-b`: Bind address (default: 0.0.0.0:443)
- `--public-ip`, `-p`: Public IP address for NAT traversal
- `--auth`, `-a`: Authentication secret for client connections
- `--verbose`, `-v`: Enable verbose logging
- `--interactive`, `-i`: Run in interactive setup mode
- `--help`, `-h`: Show help message

## Deployment

The server requires the following ports to be open:
- Main service port (default: 443)
- Health check port (8080)

For optimal NAT traversal, the server should have a public IP address.

## Docker

You can build and run the server in Docker:

```bash
# Build the Docker image
docker build -t tagio-relay-server .

# Run the container
docker run -p 443:443 -p 8080:8080 tagio-relay-server
```

## License

MIT License 