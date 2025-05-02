# TagIO Connection Test Script
# This script tests connectivity to the TagIO relay server

Write-Host "==============================================="
Write-Host "TagIO Relay Server Connection Test"
Write-Host "===============================================" 
Write-Host ""

# Test DNS resolution
Write-Host "1. Testing DNS resolution..."
$serverName = "tagio.onrender.com"
$oldServerName = "tagio-server.onrender.com"

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
    Write-Host "   ⚠️ OLD server name ($oldServerName) is also resolving" -ForegroundColor Yellow
    Write-Host "      IP Address: $($oldDnsResult.IP4Address)"
    Write-Host "      This should not be used anymore."
} catch {
    Write-Host "   ℹ️ Old server name ($oldServerName) does not resolve (this is good)" -ForegroundColor Blue
}

Write-Host ""
Write-Host "2. Testing connectivity to different ports..."

$ports = @(443, 80, 10000, 3000, 7568)

foreach ($port in $ports) {
    Write-Host "   Testing $serverName on port $port..." -NoNewline
    
    try {
        $connection = Test-NetConnection -ComputerName $serverName -Port $port -ErrorAction Stop -WarningAction SilentlyContinue
        
        if ($connection.TcpTestSucceeded) {
            if ($port -eq 443) {
                Write-Host " ✅ CONNECTED" -ForegroundColor Green
                Write-Host "      This is the PRIMARY port you should use"
            } elseif ($port -in @(80, 7568)) {
                Write-Host " ✅ CONNECTED" -ForegroundColor Green
                Write-Host "      This is a FALLBACK port"
            } else {
                Write-Host " ⚠️ CONNECTED" -ForegroundColor Yellow
                Write-Host "      This port should not be used directly"
            }
        } else {
            Write-Host " ❌ FAILED" -ForegroundColor Red
        }
    } catch {
        Write-Host " ❌ ERROR: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "3. Testing protocol detection (checking for HTTP responses)..."

# Function to test if we get HTTP response
function Test-HttpResponse {
    param (
        [string]$Server,
        [int]$Port
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Server, $Port)
        
        if ($tcpClient.Connected) {
            $stream = $tcpClient.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)
            
            # Send a simple HTTP GET request
            $writer.WriteLine("GET / HTTP/1.1")
            $writer.WriteLine("Host: $Server")
            $writer.WriteLine("Connection: Close")
            $writer.WriteLine("")
            $writer.Flush()
            
            # Read the first line of response
            $response = $reader.ReadLine()
            
            $tcpClient.Close()
            
            if ($response -like "HTTP*") {
                return $true, $response
            } else {
                return $false, $response
            }
        } else {
            return $false, "Connection failed"
        }
    } catch {
        return $false, "Error: $_"
    }
}

$portsToCheck = @(443, 80)

foreach ($port in $portsToCheck) {
    Write-Host "   Testing for HTTP response on port $port..." -NoNewline
    
    $result, $response = Test-HttpResponse -Server $serverName -Port $port
    
    if ($result) {
        Write-Host " ⚠️ RECEIVED HTTP RESPONSE" -ForegroundColor Yellow
        Write-Host "      First line: $response"
        if ($port -eq 443) {
            Write-Host "      This might be why your TagIO client is failing to connect."
            Write-Host "      Render.com is treating TCP traffic on port 443 as HTTP traffic."
        }
    } else {
        if ($response -like "Error*") {
            Write-Host " ❌ ERROR: $response" -ForegroundColor Red
        } else {
            Write-Host " ✅ NO HTTP RESPONSE (Good for TagIO protocol)" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "==============================================="
Write-Host "RECOMMENDATION:"
Write-Host "==============================================="
Write-Host "Based on the test results, you should:"
Write-Host "1. Ensure your client is using 'tagio.onrender.com' (not 'tagio-server.onrender.com')"
Write-Host "2. Connect to port 443 despite potential HTTP interference"
Write-Host "3. If using port 443 fails, try fallback ports 80 or 7568"
Write-Host ""
Write-Host "For full guidance, see client_troubleshooting.md"
Write-Host "===============================================" 