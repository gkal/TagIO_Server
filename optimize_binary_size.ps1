# Optimize Binary Size Script for TagIO
# This script builds the project in release mode and applies optimization techniques

# Build with full optimization
Write-Host "Building TagIO with optimized profile..." -ForegroundColor Green
cargo build --release --bin tagio-gui-eframe

# Get the original file size
$binary_path = ".\target\release\tagio-gui-eframe.exe"
$original_size = (Get-Item $binary_path).Length / 1KB

Write-Host "Original binary size: $($original_size.ToString("#.##")) KB" -ForegroundColor Yellow

# Strip debug symbols (though strip=true in Cargo.toml should handle this)
Write-Host "Stripping debug symbols..." -ForegroundColor Green
# For Windows, we can use strip.exe if it's available
try {
    # Check if strip utility exists
    if (Get-Command "strip" -ErrorAction SilentlyContinue) {
        strip $binary_path
    } else {
        Write-Host "strip utility not found. Consider installing it (part of MinGW or MSYS2)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error running strip: $_" -ForegroundColor Red
}

# Check if UPX is available for additional compression
try {
    if (Get-Command "upx" -ErrorAction SilentlyContinue) {
        Write-Host "Compressing with UPX..." -ForegroundColor Green
        upx --best --lzma $binary_path
    } else {
        Write-Host "UPX not found. For additional compression, install UPX from https://upx.github.io/" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error running UPX: $_" -ForegroundColor Red
}

# Get the final file size
$final_size = (Get-Item $binary_path).Length / 1KB
$reduction = 100 - ($final_size / $original_size * 100)

Write-Host "Final binary size: $($final_size.ToString("#.##")) KB" -ForegroundColor Green
Write-Host "Size reduction: $($reduction.ToString("#.##"))%" -ForegroundColor Green

Write-Host "Optimization complete!" -ForegroundColor Green
Write-Host "Binary location: $binary_path" -ForegroundColor Cyan 