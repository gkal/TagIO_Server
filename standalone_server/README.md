# TagIO Relay Server - Standalone Cloud Server

## Purpose

This is a standalone version of the TagIO relay server designed specifically for cloud deployment. It provides NAT traversal and relay services for TagIO clients.

## Features

- **NAT Traversal**: Helps clients establish peer-to-peer connections through firewalls
- **Relay Service**: Provides fallback data forwarding when direct connections aren't possible
- **Cloud-Ready**: Optimized for deployment on cloud platforms like Render.com
- **Protocol Security**: Uses protocol versioning and magic bytes for reliable connections

## Cloud Deployment

The server is designed to be deployed to `tagio-server.onrender.com:443` for production use.

### Deployment to Render.com

1. Create a new Web Service on Render.com
2. Connect your GitHub repository
3. Configure as:
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/tagio_relay_server --bind 0.0.0.0:$PORT`
   - Use environment variables for any custom configuration

## Running Locally

```bash
cargo run --release
```

Or with custom configuration:

```bash
cargo run --release -- --bind 0.0.0.0:443 --public-ip [YOUR_PUBLIC_IP] --auth [SECRET]
```

## Configuration Options

- `--bind`: Bind address (default: 0.0.0.0:443)
- `--public-ip`: Public IP address for NAT traversal (auto-detected if not provided)
- `--auth`: Authentication secret (uses default if not provided)
- `--verbose`: Enable verbose logging
- `--interactive`: Run with interactive setup prompts

## Protocol Details

This server implements the TagIO protocol (version 1) with the following features:

- Magic bytes validation (TAGIO)
- Protocol version checking
- Authenticated connections
- Robust error handling

## Building from Source

```bash
cargo build --release
```

The executable will be available at `target/release/tagio_relay_server`. 