# TagIO Client Communication Guide

## Overview

This guide details how to properly implement TagIO client communication with the TagIO HTTP Tunnel Server. The server supports two communication methods:

1. HTTP POST requests (simpler but less efficient for continuous communication)
2. WebSocket connections (preferred for persistent connections)

## WebSocket Communication Protocol

### WebSocket Connection Establishment

For WebSocket connections, clients **MUST** follow this exact sequence:

1. **Establish TCP Connection** to the server (typically on port 443 for TLS)

2. **Perform TLS Handshake** if connecting to a secure endpoint (port 443)

3. **Send WebSocket Upgrade Request**:
   ```
   GET /ws HTTP/1.1
   Host: tagio-server.onrender.com
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   Sec-WebSocket-Version: 13
   ```

4. **Wait for WebSocket Upgrade Response** (101 Switching Protocols):
   ```
   HTTP/1.1 101 Switching Protocols
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
   ```

5. **ONLY AFTER** receiving the 101 response, begin sending WebSocket frames

### Common WebSocket Implementation Errors

- **CRITICAL ERROR**: Sending WebSocket frames before receiving the 101 response
- Incorrect formatting of the Sec-WebSocket-Key header
- Not properly masking frames (all client frames must be masked)
- Not handling the WebSocket handshake timeout

## TagIO Protocol Over WebSocket

Once the WebSocket connection is established:

1. **Send Registration Message**:
   - Formatted as a WebSocket binary frame (opcode 0x02)
   - Content: Any valid TagIO protocol message (PING recommended)
   - Example: `TAGIO + Version(00 00 00 01) + "PING"`

2. **Receive TagIO ID in ACK Response**:
   - Server will respond with an ACK message containing your assigned TagIO ID
   - Format: `TAGIO + Version(00 00 00 01) + "ACK" + TagIO ID (4 bytes)`

3. **Maintain Connection**:
   - Send periodic PING messages (every 30-60 seconds recommended)
   - Process any incoming messages

### Binary Frame Formatting

All WebSocket messages must be properly formatted as WebSocket frames:

1. First byte: 
   - 0x82 for a binary frame (0x80 | 0x02)
   
2. Second byte:
   - Length byte with mask bit set (0x80 | payload length)
   - If payload length > 125, use extended length format
   
3. Masking key:
   - 4 random bytes
   
4. Payload:
   - XOR each payload byte with the corresponding masking key byte (with wraparound)

Example for small payload (< 126 bytes):
```
0x82 0x8B [4-byte mask] [masked payload bytes...]
```

## HTTP Communication Protocol

For HTTP communication:

1. **Send HTTP POST Request**:
   - Content-Type: application/octet-stream
   - Body: Raw TagIO protocol message
   
2. **Process Response**:
   - Server will respond with appropriate TagIO protocol message
   - If first connection, server will respond with ACK containing TagIO ID

## Troubleshooting

Common issues and solutions:

1. **Connection forcibly closed** - Most likely caused by:
   - Not properly implementing the WebSocket handshake
   - Sending improperly formatted WebSocket frames
   - Server behind proxy/load balancer with specific requirements

2. **TLS Alert messages (0x15)** - Indicates TLS protocol errors:
   - Improper TLS handshake
   - Incorrect protocol usage after TLS is established
   - Missing or incorrect WebSocket upgrade request

3. **No ACK response** - Could be caused by:
   - TagIO protocol message not properly formatted
   - Message not being sent as a binary WebSocket frame
   - Server not recognizing client's message format

## Testing Connection

To test WebSocket connection to the server, you can use the following command with wscat:

```bash
wscat -c wss://tagio-server.onrender.com/ws
```

Or to test HTTP communication:

```bash
curl -X POST -H "Content-Type: application/octet-stream" --data-binary "TAGIO\x00\x00\x00\x01PING" https://tagio-server.onrender.com/
``` 