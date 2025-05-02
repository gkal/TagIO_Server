# Build optimized TagIO binaries
# This script builds both the client and server with optimized settings

Write-Host "Building optimized TagIO binaries..." -ForegroundColor Cyan

# Create build directory if it doesn't exist
$buildDir = ".\target\release"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

# Build server with minimal dependencies
Write-Host "Building relay server..." -ForegroundColor Yellow
cargo build --release --bin tagio_relay_server --no-default-features --features server

# Build client with GUI
Write-Host "Building client..." -ForegroundColor Yellow
cargo build --release --bin tagio-gui --features client

# Verify the binaries exist
$serverPath = "$buildDir\tagio_relay_server.exe"
$clientPath = "$buildDir\tagio-gui.exe"

$serverExists = Test-Path $serverPath
$clientExists = Test-Path $clientPath

Write-Host "`nBuild Results:" -ForegroundColor Green
Write-Host "Server: $(if ($serverExists) { 'Success' } else { 'Failed' })" -ForegroundColor $(if ($serverExists) { 'Green' } else { 'Red' })
Write-Host "Client: $(if ($clientExists) { 'Success' } else { 'Failed' })" -ForegroundColor $(if ($clientExists) { 'Green' } else { 'Red' })

# Show file sizes
if ($serverExists) {
    $serverSize = (Get-Item $serverPath).Length
    Write-Host "Server Size: $([math]::Round($serverSize / 1MB, 2)) MB" -ForegroundColor Cyan
}

if ($clientExists) {
    $clientSize = (Get-Item $clientPath).Length
    Write-Host "Client Size: $([math]::Round($clientSize / 1MB, 2)) MB" -ForegroundColor Cyan
}

Write-Host "`nDone!" -ForegroundColor Green

# Note about running the executables
Write-Host "`nTo run the client:" -ForegroundColor Yellow
Write-Host ".\target\release\tagio-gui.exe"

Write-Host "`nTo run the relay server:" -ForegroundColor Yellow
Write-Host ".\target\release\tagio_relay_server.exe" 