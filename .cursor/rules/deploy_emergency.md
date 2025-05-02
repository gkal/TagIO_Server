# TagIO Relay Server - Emergency Deployment Procedures

This file contains emergency procedures for the TagIO Relay Server deployment on Render.com.

## Emergency Shutdown

If you need to immediately stop the TagIO Relay Server:

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Navigate to the TagIO Relay Server service
3. Click **Settings** tab
4. Scroll to the bottom of the page
5. Click the **Suspend** button

The service will immediately stop running without confirmation. When ready to restart, use the **Resume** button in the same location.

## Deployment Troubleshooting

### No Open HTTP Ports Detected

This common error happens during Render.com deployment when the port scan fails to detect your service.

**How to fix:**
1. Check health check server configuration:
   ```rust
   // Make sure this is at the start of main()
   start_health_check_server().await;
   ```

2. Verify the health check server binds to `0.0.0.0` and not localhost
3. Check the PORT environment variable is being used correctly
4. Review logs for any binding errors

### Memory Issues

If the service crashes or fails health checks:

1. Monitor memory usage in Render Dashboard
2. Consider scaling up the instance (paid plans only)
3. Add memory limits:
   ```yaml
   # render.yaml
   resources:
     memory: 512M
   ```

## Protocol Versioning

The relay server implements a versioned protocol with the following key components:

1. Client ID communication (4-byte length + ID string)
2. Authentication (optional, 4-byte length + secret)
3. Connection info sharing for NAT traversal

## Key Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server binding port | 10000 (Render) |
| PUBLIC_IP | Server's public IP | Auto-detected |
| AUTH_SECRET | Client authentication secret | None | 