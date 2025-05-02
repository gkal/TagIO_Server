# TagIO Client Port Update Guide

## Important Update for All TagIO Clients

We've made a configuration change to fix connection issues with the TagIO relay server. The server now uses **port 7568** for TCP connections instead of standard HTTP/HTTPS ports (80/443).

## How to Update Your Client

1. **Connect to the correct server address and port**:
   - Server address: `tagio-server.onrender.com` 
   - Port: `7568` (instead of 80 or 443)

2. **If your client has a configuration file**, update it with:
   ```
   relay_server = "tagio-server.onrender.com:7568"
   ```

3. **If your client uses a UI for configuration**, look for "Server Settings" or "Connection Settings" and change:
   - From: `tagio-server.onrender.com:80` or `tagio-server.onrender.com:443`
   - To: `tagio-server.onrender.com:7568`

## Why This Change Was Necessary

Render.com's infrastructure handles standard ports 80 and 443 as HTTP/HTTPS traffic, which caused protocol compatibility issues with the TagIO raw TCP protocol. Port 7568 is now configured as a non-standard port that will handle raw TCP connections properly.

## Testing Your Connection

You can verify your connection is working properly by:

1. Running the provided `test_tagio_connection.ps1` script
2. Looking for successful connection messages in your client logs
3. Checking for the absence of "Received HTTP response instead of TagIO protocol" errors

## If You Still Have Issues

If you continue to experience connection problems after updating to port 7568:

1. Try fallback ports `443` or `80` which may work in certain network environments
2. Check your firewall settings to ensure port 7568 is not blocked
3. Contact support with your client logs

## Technical Details

The server is still running internally on port 10000, but external connections are now routed through port 7568 using Render's TCP proxy feature. This approach avoids the HTTP protocol handling that was interfering with the TagIO protocol on ports 80 and 443. 