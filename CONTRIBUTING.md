# TagIO Relay Server Contributing Guidelines

## Project Overview

The TagIO Relay Server is a NAT traversal relay server built in Rust to facilitate peer-to-peer connections between clients. It acts as a signaling server to help clients establish direct connections through NAT.

## Development Rules

### Error Handling

1. **All network operations must have timeouts**:
   - Client message reads/writes should have 10-second timeouts
   - Connection establishment should have 30-second timeouts
   - Long-running health checks should have 120-second timeouts

2. **Error propagation**:
   - Use Rust's `?` operator when appropriate
   - Include context in errors: `Err(anyhow!("Failed to bind: {}", e))`
   - Log connection errors with client identifiers

3. **Resource cleanup**:
   - Ensure client connections are properly removed from the registry on disconnect
   - Close idle connections after 120 seconds of inactivity
   - Implement graceful shutdown to clean up resources

### Deployment Guidelines

1. **Render.com Deployment**:
   - Always start health check servers before main application logic
   - Bind to `0.0.0.0` for all network services
   - Listen on multiple ports (3000, 10000, 8080, 80) for health checks
   - Use the `PORT` environment variable provided by Render

2. **Environment Variables**:
   - `PORT`: Server binding port (set by Render.com)
   - `PUBLIC_IP`: For NAT traversal (auto-detected or manually set)
   - `AUTH_SECRET`: Optional authentication secret
   - `RENDER`: Auto-set by Render.com to indicate cloud environment

3. **IP Detection**:
   - Auto-detect outbound IP on Render.com deployments
   - Test multiple external services (api.ipify.org, ifconfig.me)
   - Store detected IP for consistent client communication

## Emergency Procedures

### Emergency Shutdown on Render.com

If the server needs to be stopped immediately:

1. Go to the [Render Dashboard](https://dashboard.render.com/)
2. Navigate to your TagIO Relay Server service
3. Go to the **Settings** tab
4. Scroll to the bottom and click **Suspend**

The service will immediately stop running. Resume when ready by clicking **Resume** in the same location.

### Handling Runaway Processes

If the server has excessive resource usage:

1. **Monitor** the service resources in the Render dashboard
2. If memory/CPU usage is abnormal, **Suspend** the service
3. Check logs for potential causes (connection flooding, memory leaks)
4. Fix the code and deploy a new version

### Debugging Deployment Issues

For "No open HTTP ports detected" errors:

1. Ensure health check servers start first (they're already implemented)
2. Check if the service binds to the correct port (from `PORT` env var)
3. Verify that the health check returns proper HTTP responses
4. Check resource limits (memory/CPU) in the Render dashboard

## Common Error Cases

| Error | Cause | Solution |
|-------|-------|----------|
| No open HTTP ports detected | Server fails to bind to ports or start HTTP server | Ensure health check server starts first |
| Connection timeout | Client-server communication issue | Implement proper timeout handling |
| Authentication failure | Invalid auth secret | Make sure AUTH_SECRET matches on server and client |
| Failed outbound IP detection | Network or service issues | Fallback to manual PUBLIC_IP setting |
| Memory limit exceeded | Too many connections or memory leak | Implement connection limits and monitor usage |

## Pull Request Guidelines

1. Ensure all code changes include proper error handling
2. Add timeout mechanisms to all network operations
3. Maintain backward compatibility with existing clients
4. Test deployment on Render.com before merging
5. Update documentation to reflect changes 