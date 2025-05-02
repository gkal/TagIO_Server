# TagIO

## Overview
TagIO is a secure remote desktop application that provides NAT traversal capabilities for peer-to-peer connections.

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
