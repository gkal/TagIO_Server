# TagIO Client Connection Troubleshooting

## Common Connection Issues

Based on recent logs, we've identified that clients may be experiencing connection issues when trying to connect to the TagIO relay server. This guide will help you resolve these issues.

## Quick Fix

The most common issue is that your client is trying to connect to the wrong server hostname. 

### Update Your Client Configuration

1. Your client is likely trying to connect to `tagio-server.onrender.com` 
2. The correct server address is `tagio.onrender.com` (without the "-server" part)

#### How to Update Your Configuration:

1. Open your TagIO client
2. Go to Settings or Configuration menu
3. Look for "Relay Server" or "Server Address" setting
4. Change it from `tagio-server.onrender.com:443` to `tagio.onrender.com:443`
5. Save your settings and restart the client

## Server Port Information

The TagIO relay server is properly configured on the following ports:

- **Primary Connection (Recommended)**: `tagio.onrender.com:443`
- **Fallback Ports (if 443 is blocked)**:
  - Port 80 (HTTP alternative)
  - Port 7568 (non-standard port)

## Protocol Issues

If you're still seeing "Received HTTP response instead of TagIO protocol" errors, this is likely because:

1. Render.com's infrastructure is treating port 443 traffic as HTTP
2. Our server team is working to resolve this issue with Render.com

## Manual Configuration Option

If the automatic settings don't work, you can manually edit your configuration file:

1. Look for a file named `tagio_config.json` or similar in your application data folder:
   - Windows: `%APPDATA%\tagio\`
   - macOS: `~/Library/Application Support/tagio/`
   - Linux: `~/.config/tagio/`

2. Edit the file and ensure the `relay_server` field is set to `tagio.onrender.com:443`

## Need More Help?

If you continue to experience issues connecting to the relay server, please contact support with:

1. Your client logs (found in the application data folder)
2. Description of any firewall or network restrictions in your environment 
3. What server address you're trying to connect to 