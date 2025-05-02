# TagIO Render Server Deployment

This document explains how to use the TagIO relay server hosted on Render.com.

## Relay Server

The TagIO relay server is now hosted at `tagio.onrender.com` on port 443.

### Key Details:

- **Server URL**: `tagio.onrender.com:443`
- **Default Auth Secret**: `tagio_default_secret`

## How it Works

1. The client application (`tagio-gui`) connects to the relay server for NAT traversal
2. The relay server facilitates peer discovery and connection establishment
3. Once peers are connected, communication happens directly between them when possible

## Client Configuration

The client has been automatically configured to use the new Render server. The default settings in the configuration file now point to `tagio.onrender.com:443`.

If you need to manually update the relay server:

1. Edit your configuration file
2. Set `relay_server` to `tagio.onrender.com:443`

## Optimizations

The build process has been optimized to reduce dependencies:

1. Feature flags have been added to separate client and server code
2. The server now builds without GUI dependencies (no GTK/eframe)
3. Server binary size has been reduced to ~1.1MB

## Deployment Options

### Deploy on Render

The `render.yaml` file in the repository configures automatic deployment to Render.com.

### Docker Deployment

A Dockerfile is included for containerized deployment:

```bash
# Build the Docker image
docker build -t tagio-relay .

# Run the container
docker run -p 443:443 -p 8080:8080 -e AUTH_SECRET=your_secret_key tagio-relay
```

### Manual Build

To build the server without GUI dependencies:

```bash
cargo build --release --bin tagio_relay_server --no-default-features --features server
```

Or use the provided build script:

```bash
./build_optimized.ps1
```

## Benefits of the Render Deployment

- **Always-on service**: The server runs 24/7 without requiring you to manage infrastructure
- **HTTPS support**: Uses TLS for secure connections
- **Free tier**: Hosted on Render's free tier (with some limitations)

## Limitations

- Free tier has cold starts (first connection might be slow)
- Limited resources and bandwidth
- No guaranteed uptime SLA

## For Developers

### Render Deployment

The server is deployed through a `render.yaml` configuration file that specifies:

```yaml
services:
  - type: web
    name: tagio-relay
    runtime: rust
    plan: free
    buildCommand: cargo build --release --bin tagio_relay_server
    startCommand: ./target/release/tagio_relay_server
    envVars:
      - key: PUBLIC_IP
        value: automatic
      - key: AUTH_SECRET
        value: tagio_default_secret
```

### Dependency Optimization

The project has been optimized to reduce the binary size and compile time:

1. Removed unnecessary dependencies
2. Limited feature flags to only what's needed
3. Optimized build settings for smaller binaries

### Running Your Own Server

If you prefer to run your own relay server:

1. Build the server: `cargo build --release --bin tagio_relay_server`
2. Run with environment variables:
   ```
   PUBLIC_IP=your_public_ip AUTH_SECRET=your_secret ./target/release/tagio_relay_server
   ```
3. Update the client config to point to your server 