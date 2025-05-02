# TagIO

## Overview
TagIO is a secure remote desktop application that provides NAT traversal capabilities for peer-to-peer connections.

## Hosted Relay Server

The TagIO relay server is now hosted on Render.com:
- **Server URL**: `tagio-server.onrender.com:443`
- **Documentation**: See `docs/render_server.md` for details

The client automatically uses this hosted server by default, so no configuration is needed.

## Recent Updates

- **Protocol Versioning**: Added protocol versioning and magic bytes to improve connection reliability
- **Error Handling**: Enhanced error detection for malformed messages and protocol mismatches
- **HTTP Detection**: The server now properly responds to HTTP requests with an informative message

## Project Structure

### Executables

⚠️ **CRITICAL WARNING** ⚠️

This project must ONLY build the following two executables:
1. `tagio-gui` - The client application
2. `tagio_relay_server` - The relay server

**DO NOT add any other binary targets to the Cargo.toml file.**

### Running the Applications

#### Relay Server
To run the relay server:
```
target/release/tagio_relay_server.exe
```

The server can be configured with command line options:
```
target/release/tagio_relay_server.exe --bind 0.0.0.0:443 --public-ip YOUR_PUBLIC_IP --auth YOUR_SECRET
```

Or without parameters for an interactive setup.

#### Client
To run the client application:
```
target/release/tagio-gui.exe
```

### Building
To build both applications:
```
cargo build --release
```

This will create the executables in the `target/release` directory.

## Development Guidelines

1. Keep the binary targets limited to only the two specified executables
2. Maintain a clean separation between client and server code
3. Use the existing code style and patterns for consistency
4. Test thoroughly before deploying to production

## Key Features

- **Zero Port Forwarding**: Connect between different networks with no router configuration required
- **Pure Rust Implementation**: No external dependencies or installations needed
- **Similar to AnyDesk/TeamViewer**: Uses advanced NAT traversal techniques
- **Secure Connections**: End-to-end encryption for all connections
- **Lightweight and Fast**: Minimal resource usage

## How It Works

TagIO implements multiple NAT traversal techniques completely in Rust:

1. **UDP Hole Punching**: Creates temporary openings in firewalls to establish direct connections
2. **Connection Brokering**: A central relay server helps clients find each other
3. **STUN-like Techniques**: Discovers public IP/port information
4. **Automatic Fallback**: If direct connection fails, falls back to relaying data

## Usage

### Running the Relay Server

The relay server helps clients connect to each other when they're behind NAT or firewalls. It facilitates NAT traversal and provides fallback relay functionality when direct connections aren't possible.

```bash
# Basic usage
relay_server

# With custom bind address and TLS certificates
relay_server --bind 0.0.0.0:8443 --cert path/to/cert.pem --key path/to/key.pem

# With explicit public IP (recommended for production)
relay_server --public-ip 123.45.67.89
```

### Options

- `--bind`, `-b`: Bind address (default: 0.0.0.0:443)
- `--cert`, `-c`: TLS certificate path (default: certs/cert.pem)
- `--key`, `-k`: TLS private key path (default: certs/key.pem)
- `--public-ip`, `-p`: Public IP address for NAT traversal
- `--help`, `-h`: Show help message

### Running the Client

```bash
cargo run --release --bin tagio-cmd -- [server|client] [options]
```

Server mode (wait for connections):
```bash
cargo run --release --bin tagio-cmd -- server
```

Client mode (connect to another instance):
```bash
cargo run --release --bin tagio-cmd -- client CLIENT_ID
```

Where CLIENT_ID is the ID displayed by the server instance.

## Technical Details

This solution implements the following NAT traversal techniques:

1. **Signaling Server**: Facilitates connection establishment between peers
2. **UDP Hole Punching**: Sends packets to create "holes" in NAT devices
3. **Connection Reversal**: For asymmetric NATs where only one side is behind NAT
4. **Relay Fallback**: When direct connection isn't possible

## License

MIT License

## Acknowledgements

Inspired by projects like:
- [rathole](https://github.com/rapiz1/rathole)
- [crab_nat](https://github.com/ryco117/crab_nat)
- [nat_traversal](https://github.com/maidsafe-archive/nat_traversal)

# TagIO Relay Server

A NAT traversal and relay server for TagIO remote desktop connections.

## Server Configuration

The TagIO Relay Server is designed to run on [Render](https://render.com) and facilitate connections between TagIO clients.

### Server Features

- NAT traversal to establish direct peer-to-peer connections
- Fallback relay functionality when direct connections aren't possible
- Health check endpoints for cloud provider verification
- Authentication to secure connections
- Support for automatic port binding in cloud environments

## Client Configuration

When connecting to the TagIO Relay Server on Render, use the following settings:

### Server Connection Settings

- **Server address:** `tagio.onrender.com`
- **Port:** `443` (NOT port 10000)
- **Protocol:** TagIO NAT Traversal Protocol v1
- **Fallback ports:** `80` (if 443 is blocked)

### Connection Troubleshooting

1. **Cannot connect to server:**
   - Verify you're using port 443, not port 10000
   - Check your network firewall isn't blocking outbound HTTPS traffic
   - Try the fallback port 80 if port 443 is blocked

2. **Authentication errors:**
   - Ensure you're using the correct authentication token
   - Default token is "tagio_default_secret" unless customized

3. **Protocol errors:**
   - Ensure you're using the TagIO protocol, not attempting an HTTP connection
   - Make sure your client software is updated to the latest version

## Running the Server Locally

To run the server locally for development:

```bash
cargo run --bin tagio_relay_server -- --bind 0.0.0.0:10000 --verbose
```

## Production Deployment

The server is designed to be deployed to Render.com with the following environment:

- **PORT:** Set to `10000` (for internal binding)
- **Public URL:** Will be available at `tagio.onrender.com:443`

Important: Clients should always connect to the public URL on port 443, not the internal port.

## 🔧 Tech Stack

- **Language**: Rust
- **Runtime**: Tokio async runtime
- **Networking**: TCP sockets
- **Deployment**: Render.com
- **Dependencies**: tokio, reqwest, anyhow

## 🚀 Quick Start

### Local Development

```bash
# Build the project
cargo build --release

# Run locally
cargo run --release --bin tagio_relay_server
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server binding port | 8443 (local), 10000 (Render) |
| PUBLIC_IP | Server public IP for NAT traversal | Auto-detected |
| AUTH_SECRET | Optional client authentication secret | None (auth disabled) |

## 🛑 Emergency Procedures

### Render.com Emergency Shutdown

```
Quick Reference for Cursor AI:
1. Go to Render Dashboard: https://dashboard.render.com/
2. Select TagIO Relay Server service
3. Navigate to Settings tab
4. Scroll to bottom
5. Click "Suspend" button
```

The service will immediately stop running. Resume when ready by clicking "Resume" in the same location.

### Deployment Troubleshooting

For "No open HTTP ports detected":
- The server now auto-starts a health check server on ports 3000, 10000, 8080, or 80
- It binds to 0.0.0.0 to ensure external access
- HTTP responses are properly formatted with Content-Length

### Resource Management

If experiencing memory issues:
- Default settings work fine up to ~100 concurrent clients
- For more clients, consider scaling the instance on Render
- Monitor memory usage in the Render dashboard

## 📋 Client Protocol

1. Client connects to server on TCP
2. Client sends 4-byte length followed by ID string
3. Authentication (optional): 4-byte length followed by secret
4. Server sends acknowledgment with public address
5. Clients can query for other clients by ID
6. Server facilitates hole-punching by sharing endpoints

## 📚 Development Guidelines

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full development guidelines, including:
- Error handling rules
- Deployment procedures
- Timeout configurations
- Pull request guidelines

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration
```
