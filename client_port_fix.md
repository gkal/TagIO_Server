# TagIO Client Port Update Guide

## Important Update for All TagIO Clients

We've made a configuration change to fix connection issues with the TagIO relay server. The server now uses **port 80** instead of port 443 for TCP connections.

## How to Update Your Client

1. **Connect to the correct server address and port**:
   - Server address: `tagio-server.onrender.com` 
   - Port: `80` (instead of 443)

2. **If your client has a configuration file**, update it with:
   ```
   relay_server = "tagio-server.onrender.com:80"
   ```

3. **If your client uses a UI for configuration**, look for "Server Settings" or "Connection Settings" and change:
   - From: `tagio-server.onrender.com:443`
   - To: `tagio-server.onrender.com:80`

## Why This Change Was Necessary

Render.com's infrastructure handles port 443 as HTTP/HTTPS traffic, which caused protocol compatibility issues with the TagIO raw TCP protocol. Port 80 is now configured to handle raw TCP connections properly.

## Testing Your Connection

You can verify your connection is working properly by:

1. Running the provided `test_tagio_connection.ps1` script
2. Looking for successful connection messages in your client logs
3. Checking for the absence of "Received HTTP response instead of TagIO protocol" errors

## If You Still Have Issues

If you continue to experience connection problems after updating to port 80:

1. Try the fallback port `7568` which is configured for direct TCP connections
2. Check your firewall settings to ensure port 80 is not blocked
3. Contact support with your client logs

## Technical Details

The server is still running internally on port 10000, but external connections are now routed through port 80 using Render's TCP proxy feature. This avoids the HTTP protocol handling that was interfering with the TagIO protocol on port 443. 