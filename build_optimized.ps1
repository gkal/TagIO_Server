# Build optimized TagIO binaries
# This script builds both the client and server with optimized settings

Write-Host "Building optimized TagIO binaries..." -ForegroundColor Cyan

# Create build directory if it doesn't exist
$buildDir = ".\target\release"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

# Build with optimized settings
Write-Host "Building relay server..." -ForegroundColor Yellow
cargo build --release --bin tagio_relay_server

Write-Host "Building client..." -ForegroundColor Yellow
cargo build --release --bin tagio-gui

# Verify the binaries exist
$serverPath = "$buildDir\tagio_relay_server.exe"
$clientPath = "$buildDir\tagio-gui.exe"

$serverExists = Test-Path $serverPath
$clientExists = Test-Path $clientPath

Write-Host "`nBuild Results:" -ForegroundColor Green
Write-Host "- Relay Server: $(if ($serverExists) { 'SUCCESS' } else { 'FAILED' })"
Write-Host "- Client: $(if ($clientExists) { 'SUCCESS' } else { 'FAILED' })"

if ($serverExists -and $clientExists) {
    # Get file sizes
    $serverSize = (Get-Item $serverPath).Length / 1MB
    $clientSize = (Get-Item $clientPath).Length / 1MB
    
    Write-Host "`nBinary Sizes:" -ForegroundColor Cyan
    Write-Host "- Relay Server: $($serverSize.ToString('0.00')) MB"
    Write-Host "- Client: $($clientSize.ToString('0.00')) MB"
    
    Write-Host "`nBuild completed successfully!" -ForegroundColor Green
    Write-Host "Files are located at: $buildDir"
} else {
    Write-Host "`nBuild failed!" -ForegroundColor Red
}

# Note about running the executables
Write-Host "`nTo run the client:" -ForegroundColor Yellow
Write-Host ".\target\release\tagio-gui.exe"

Write-Host "`nTo run the relay server:" -ForegroundColor Yellow
Write-Host ".\target\release\tagio_relay_server.exe" 