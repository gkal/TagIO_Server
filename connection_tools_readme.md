# TagIO Connection Troubleshooting Tools

This directory contains several tools to help diagnose and fix connection issues with the TagIO relay server.

## Understanding the Issue

The most common connection issue is that clients are trying to connect to the wrong hostname:
- **Wrong hostname**: `tagio-server.onrender.com`
- **Correct hostname**: `tagio.onrender.com`

Additionally, there's an issue with Render.com's infrastructure treating port 443 connections as HTTP traffic instead of the TagIO protocol.

## Tools Available

### 1. Client Troubleshooting Guide

**File**: `client_troubleshooting.md`

This document provides step-by-step instructions for updating your client configuration to use the correct server address.

### 2. PowerShell Connection Test Script

**File**: `test_tagio_connection.ps1`

A Windows PowerShell script that tests various aspects of connectivity to the TagIO relay server:
- DNS resolution
- Port accessibility
- Protocol detection

**Usage**:
```powershell
# Run in PowerShell
.\test_tagio_connection.ps1
```

### 3. Rust Protocol Test Tool

**File**: `test_tagio_protocol.rs`

A standalone Rust program that tests the TagIO protocol connection to the relay server. This is more advanced and requires Rust to compile.

**Usage**:
```bash
# Compile the tool
rustc test_tagio_protocol.rs

# Run with default settings (tagio.onrender.com:443)
./test_tagio_protocol

# Run with custom server and port
./test_tagio_protocol tagio.onrender.com 80
```

## Steps to Fix Connection Issues

1. First, update your client configuration to use `tagio.onrender.com` instead of `tagio-server.onrender.com`.

2. If you still have issues, run the PowerShell test script to diagnose the problem:
   ```powershell
   .\test_tagio_connection.ps1
   ```

3. If the script shows port 443 returns HTTP responses, try using fallback ports 80 or 7568 in your client configuration.

4. For advanced users, compile and run the Rust test tool to check if the TagIO protocol is working correctly:
   ```bash
   rustc test_tagio_protocol.rs
   ./test_tagio_protocol
   ```

## Known Limitations

1. **Port 443 HTTP Treatment**: Render.com treats port 443 traffic as HTTP traffic, which can interfere with the TagIO protocol. This is a limitation of Render's infrastructure and unfortunately can't be fixed on our end.

2. **Fallback Ports**: The client should automatically try fallback ports (80, 3000, 7568) if port 443 fails, but you can also manually configure it to use these ports directly. 