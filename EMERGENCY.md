# TagIO Relay Server Emergency Procedures

## 🚨 Emergency Shutdown on Render.com

```
EMERGENCY_SHUTDOWN_RENDER = {
  "steps": [
    "Go to https://dashboard.render.com/",
    "Select the TagIO Relay Server service",
    "Click Settings tab",
    "Scroll to bottom",
    "Click Suspend button"
  ],
  "notes": "Service stops immediately. No confirmation needed. Billing stops for paid plans."
}
```

## 🔄 Recover from Failed Deployment

```
RECOVER_NO_PORTS_DETECTED = {
  "issue": "No open HTTP ports detected",
  "causes": [
    "Health check server not binding properly",
    "Wrong IP binding (needs 0.0.0.0)",
    "PORT env var not used correctly",
    "Memory limits exceeded"
  ],
  "fix": [
    "Check logs for binding errors",
    "Verify health_check_server binds to 0.0.0.0",
    "Try manual redeploy",
    "If persists, add 'timeout_ms=300000' to render.yaml"
  ]
}
```

## 💾 Memory Issues

```
MEMORY_TROUBLESHOOTING = {
  "symptoms": [
    "Service crashes unexpectedly",
    "Client connections drop",
    "Deploy succeeds but health check fails"
  ],
  "fixes": [
    "Scale up instance on Render (if on paid plan)",
    "Implement connection limits (max 100 on free tier)",
    "Add memory_limit_mb=512 to render.yaml",
    "Check for memory leaks in connection handling"
  ]
}
```

## 🔒 Authentication Issues

```
AUTH_TROUBLESHOOTING = {
  "symptoms": [
    "Clients fail to connect with auth errors",
    "Authentication handshake fails"
  ],
  "checks": [
    "Verify AUTH_SECRET environment variable is set",
    "Check client is sending correct auth format",
    "Ensure auth_secret length matches expected"
  ],
  "emergency_disable": "To temporarily disable auth, remove AUTH_SECRET env var"
}
```

## 📡 NAT Traversal Problems

```
NAT_TRAVERSAL_ISSUES = {
  "symptoms": [
    "Clients can connect to relay but not to each other",
    "NAT hole punching fails"
  ],
  "fixes": [
    "Verify PUBLIC_IP is correctly set",
    "Check that auto-detection is working",
    "Manually set PUBLIC_IP in environment variables",
    "Verify client handling of connection info messages"
  ]
}
```

## ⚡ Quick Commands for SSH Access (If Enabled)

```
QUICK_SSH_COMMANDS = {
  "check_logs": "journalctl -u tagio-relay-server -f",
  "view_connections": "netstat -an | grep ESTABLISHED | wc -l",
  "restart_service": "Not available on Render - use dashboard",
  "check_resources": "free -m; top -b -n 1"
}
```

## 📊 Monitoring Checklist

```
MONITORING_CHECKLIST = {
  "daily": [
    "Check error rate in Render logs",
    "Monitor client connection count",
    "Verify health check is responding"
  ],
  "weekly": [
    "Check memory usage trends",
    "Review any authentication failures",
    "Verify auto-scaling is working (paid plans)"
  ]
}
``` 