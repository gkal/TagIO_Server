# TagIO Connection Test Script
# This script tests connectivity to the TagIO relay server

Write-Host "==============================================="
Write-Host "TagIO Relay Server Connection Test"
Write-Host "===============================================" 
Write-Host ""

# Test DNS resolution
Write-Host "1. Testing DNS resolution..."
$serverName = "tagio-server.onrender.com"
$oldServerName = "tagio.onrender.com"

try {
    $dnsResult = Resolve-DnsName -Name $serverName -ErrorAction Stop
    Write-Host "   ✅ DNS Resolution successful for $serverName" -ForegroundColor Green
    Write-Host "      IP Address: $($dnsResult.IP4Address)"
} catch {
    Write-Host "   ❌ DNS Resolution failed for $serverName" -ForegroundColor Red
    Write-Host "      Error: $_"
}

try {
    $oldDnsResult = Resolve-DnsName -Name $oldServerName -ErrorAction Stop
    Write-Host "   ℹ️ DNS Resolution also successful for $oldServerName" -ForegroundColor Blue
    Write-Host "      IP Address: $($oldDnsResult.IP4Address)"
} catch {
    Write-Host "   ❓ DNS Resolution failed for $oldServerName" -ForegroundColor Yellow
    Write-Host "      Error: $_"
}

Write-Host ""
Write-Host "2. Testing TCP connectivity..."

# Test port 80 (Primary TCP port)
Write-Host "   Testing connection to $serverName:80 (Primary TCP port)..."
try {
    $tcp80Result = Test-NetConnection -ComputerName $serverName -Port 80 -ErrorAction Stop -WarningAction SilentlyContinue
    if ($tcp80Result.TcpTestSucceeded) {
        Write-Host "   ✅ Successfully connected to $serverName:80" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Failed to connect to $serverName:80" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing connection to $serverName:80" -ForegroundColor Red
    Write-Host "      Error: $_"
}

# Test port 443 (Alternative port)
Write-Host "   Testing connection to $serverName:443 (Alternative port)..."
try {
    $tcp443Result = Test-NetConnection -ComputerName $serverName -Port 443 -ErrorAction Stop -WarningAction SilentlyContinue
    if ($tcp443Result.TcpTestSucceeded) {
        Write-Host "   ✅ Successfully connected to $serverName:443" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Failed to connect to $serverName:443" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing connection to $serverName:443" -ForegroundColor Red
    Write-Host "      Error: $_"
}

# Test port 7568 (Fallback port)
Write-Host "   Testing connection to $serverName:7568 (Fallback port)..."
try {
    $tcp7568Result = Test-NetConnection -ComputerName $serverName -Port 7568 -ErrorAction Stop -WarningAction SilentlyContinue
    if ($tcp7568Result.TcpTestSucceeded) {
        Write-Host "   ✅ Successfully connected to $serverName:7568" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Failed to connect to $serverName:7568" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing connection to $serverName:7568" -ForegroundColor Red
    Write-Host "      Error: $_"
}

Write-Host ""
Write-Host "3. Summary:"
Write-Host "--------------------------------------------------------"
$dnsStatus = if ($null -ne $dnsResult) { "✅ Success" } else { "❌ Failed" }
$port80Status = if ($tcp80Result.TcpTestSucceeded) { "✅ Success" } else { "❌ Failed" }
$port443Status = if ($tcp443Result.TcpTestSucceeded) { "✅ Success" } else { "❌ Failed" }
$port7568Status = if ($tcp7568Result.TcpTestSucceeded) { "✅ Success" } else { "❌ Failed" }

Write-Host "DNS Resolution:         $dnsStatus"
Write-Host "Port 80 (Primary):      $port80Status"
Write-Host "Port 443 (Alternative): $port443Status"
Write-Host "Port 7568 (Fallback):   $port7568Status"
Write-Host "--------------------------------------------------------"
Write-Host ""

if ($tcp80Result.TcpTestSucceeded) {
    Write-Host "✅ Primary connection test successful!" -ForegroundColor Green
    Write-Host "   Your client should be able to connect to the TagIO relay server."
} else {
    if ($tcp443Result.TcpTestSucceeded -or $tcp7568Result.TcpTestSucceeded) {
        Write-Host "⚠️ Primary connection failed, but alternative ports are available." -ForegroundColor Yellow
        Write-Host "   You may need to configure your client to use a different port."
    } else {
        Write-Host "❌ All connection tests failed!" -ForegroundColor Red
        Write-Host "   Please check your network configuration or contact support."
    }
}

Write-Host ""
Write-Host "For client configuration help, see the client_port_fix.md file."
Write-Host "===============================================" 