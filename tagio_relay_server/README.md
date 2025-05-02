# TagIO Relay Server

## Overview
This is a standalone NAT traversal relay server for TagIO remote desktop applications. It facilitates connections between clients that are behind NAT/firewalls.

## Server Configuration

### Default Server Address
The server is configured to use the following default settings:
- Bind address: `0.0.0.0:443` (listens on all interfaces, port 443)
- Public server address: `tagio-server.onrender.com:443` (for clients to connect to)

**IMPORTANT NOTE:** The public server address has been updated from `tagio.onrender.com` to `tagio-server.onrender.com`. Client applications should be updated to use this new address.

### Authentication
The server uses a default authentication secret (`tagio_default_secret`). For production use, it's recommended to change this using the `--auth` parameter.

## Running the Server

### Basic Usage
```
tagio_relay_server.exe
```

### With Custom Configuration
```
tagio_relay_server.exe --bind 0.0.0.0:443 --public-ip your.ip.address --auth your_secret
```

### Interactive Mode
```
tagio_relay_server.exe --interactive
```

## Client Integration
Clients should be configured to connect to:
```
tagio-server.onrender.com:443
```

For client developers: Make sure to update your client code to use the new server address. The server is hosted on Render.com and provides NAT traversal capabilities for peer-to-peer connections. 