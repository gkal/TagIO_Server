# TagIO Client Configuration Guide

## Connection Settings for TagIO Relay Server

When connecting your TagIO client to our relay server hosted on Render.com, please use these settings:

### Primary Connection (Recommended)

- **Server Address:** `tagio.onrender.com`
- **Port:** `443`
- **Protocol:** TagIO NAT Traversal Protocol
- **Authentication:** Required (default token: "tagio_default_secret")

### Fallback Connection (If Primary Fails)

- **Server Address:** `tagio.onrender.com`
- **Port:** `80`
- **Protocol:** TagIO NAT Traversal Protocol
- **Authentication:** Required (default token: "tagio_default_secret")

## Common Connection Issues

### 1. Connection Timeouts

If you experience connection timeouts when trying to connect to port 10000, you're using the wrong port. Render.com does not expose port 10000 externally.

**Solution:** Always connect to port 443, not port 10000.

### 2. Protocol Errors

If you receive "HTTP protocol detected" or similar errors, your client might be sending HTTP requests instead of using the TagIO protocol.

**Solution:** Make sure your client is properly configured to use the TagIO protocol, not HTTP.

### 3. Authentication Failures

If authentication fails, ensure you're using the correct token (default: "tagio_default_secret" unless changed by the administrator).

### 4. Port Restrictions

If your network blocks outbound port 443, try connecting to port 80. If both are blocked, contact your network administrator.

## Need Help?

If you continue to experience connection issues, please contact the server administrator with the following information:

1. Your client version
2. Exact error message
3. What port you're trying to connect to
4. Any firewalls or network restrictions in your environment 