# TagIO HTTP Tunnel Server Architecture

## Overview

The TagIO HTTP Tunnel Server is a communication relay for TagIO clients, supporting both WebSocket and HTTP tunneling to facilitate communication between devices that may be behind firewalls or NAT. The server is built in Rust using the Tokio async runtime.

## Core Components

1. **HTTP Server (hyper)**: Listens for incoming connections, handles WebSocket upgrades
2. **WebSocket Handler**: Processes WebSocket connections and messages
3. **Client Registry**: Tracks connected clients with unique IDs
4. **TagIO Protocol Handler**: Processes and routes TagIO protocol messages

## TagIO Protocol Specification

### Message Format
- All messages start with `TAGIO` magic bytes (5 bytes: 0x54 0x41 0x47 0x49 0x4F)
- Followed by protocol version (4 bytes, little-endian)
- Followed by message type (3+ bytes, ASCII string)
- Followed by optional payload

### Core Message Types
1. **PING**: Client to server heartbeat
   - Format: `TAGIO + Version(00 00 00 01) + "PING"`
   - Binary: `54 41 47 49 4F 00 00 00 01 50 49 4E 47`

2. **ACK**: Server to client acknowledgment
   - Format: `TAGIO + Version(00 00 00 01) + "ACK" + TagIO ID (4 bytes, little-endian)`
   - Example: `54 41 47 49 4F 00 00 00 01 41 43 4B XX XX XX XX`

3. **MSG**: Bidirectional message between clients
   - Format: `TAGIO + Version(00 00 00 01) + "MSG" + Target ID (4 bytes) + [Payload]`
   - Example: `54 41 47 49 4F 00 00 00 01 4D 53 47 XX XX XX XX [payload data]`

## Server Implementation Details

### Key Functions
1. `handle_http_request`: Entry point for all incoming HTTP requests
2. `handle_websocket_client_registration`: Handles WebSocket connection lifecycle
3. `handle_ws_binary_message`: Processes WebSocket binary frames
4. `handle_tagio_over_http`: Processes TagIO messages sent over HTTP
5. `create_tagio_ack_response`: Creates ACK responses with client IDs
6. `find_tagio_magic`: Detects TagIO protocol messages in data streams
7. `register_client`: Registers clients in the global registry
8. `generate_unique_tagio_id`: Creates unique IDs for new clients

### Client Connection & Registration Flow
1. Client establishes TCP connection to server (HTTP or WebSocket)
2. For WebSocket:
   - Client sends HTTP upgrade request with WebSocket headers
   - Server responds with 101 Switching Protocols
   - Client sends any TagIO message
   - Server assigns a unique TagIO ID and responds with ACK
3. For HTTP:
   - Client sends HTTP POST with TagIO protocol data in body
   - Server processes message and responds with appropriate response

### WebSocket Handling Requirements
- Properly implement WebSocket handshake (HTTP upgrade)
- All TagIO messages over WebSocket must be sent as binary frames
- WebSocket frames must be properly masked by client

### Error Handling
- Connection timeout handling
- Client registry cleanup for stale connections
- Protocol error detection and recovery

## Configuration Options
- Port: Default 10000, can be overridden via environment variable PORT
- Log level: Configure via command line args
- TLS support: Optional, can be enabled with cert and key files

## Deployment Considerations
- Server designed to work behind proxies (Cloudflare, Render)
- Handles SSL termination from proxies
- Extracts client IP from X-Forwarded-For and X-Real-IP headers

## Key Dependencies
- hyper: HTTP server framework
- tokio: Async runtime
- hyper-tungstenite: WebSocket support
- log/fern: Logging infrastructure
- clap: Command line argument parsing

## Critical Code Constraints
- The server MUST properly respond to WebSocket upgrade requests
- All responses to WebSocket clients MUST be properly framed
- ACK responses MUST include valid TagIO IDs
- Client registry MUST be protected against concurrent access issues 