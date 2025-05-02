# TagIO Client Port Update Guide

## Important Update for All TagIO Clients

We've made a configuration change to fix connection issues with the TagIO relay server. The server now implements **protocol detection** on port 80 to properly handle TagIO connections.

## How to Update Your Client

1. **Connect to the correct server address and port**:
   - Server address: `tagio-server.onrender.com` 
   - Port: `80`

2. **If your client has a configuration file**, update it with:
   ```
   relay_server = "tagio-server.onrender.com:80"
   ```

3. **If your client uses a UI for configuration**, look for "Server Settings" or "Connection Settings" and change:
   - From: Any previous port configuration (443, 7568, etc.)
   - To: `tagio-server.onrender.com:80`

## Why This Change Was Necessary

Render.com's infrastructure has limitations on exposing custom TCP ports. We've implemented protocol detection on the standard HTTP port (80) to distinguish between web traffic and TagIO protocol connections.

## Protocol Detection Explained

When a connection is made to port 80:
1. The server will examine the first few bytes of the connection
2. If it's an HTTP request, it will be handled as web traffic
3. If it's a TagIO protocol message, it will be processed by the relay server

This approach allows both web browsers and TagIO clients to connect to the same port but receive appropriate handling.

## Testing Your Connection

You can verify your connection is working properly by:

1. Running the provided `test_tagio_connection.ps1` script
2. Looking for successful connection messages in your client logs
3. Checking for the absence of "Received HTTP response instead of TagIO protocol" errors

## If You Still Have Issues

If you continue to experience connection problems:

1. Try port 443 as an alternative
2. Check your firewall settings to ensure port 80 is not blocked
3. Contact support with your client logs

## Technical Details

The server is running internally on port 10000, with connections from port 80 forwarded by Render's infrastructure. The server now implements protocol detection to distinguish between HTTP web traffic and TagIO protocol messages, allowing both to share the same port. 