# Script to analyze binary size of TagIO
# Requires cargo-bloat - install with: cargo install cargo-bloat

# Check if cargo-bloat is installed
try {
    $null = cargo bloat --help
} catch {
    Write-Host "cargo-bloat not found. Installing..." -ForegroundColor Yellow
    cargo install cargo-bloat
}

# Analyze binary size by crates
Write-Host "Analyzing binary size by crates..." -ForegroundColor Green
cargo bloat --release --bin tagio-gui-eframe

# Analyze binary size by functions
Write-Host "`nAnalyzing binary size by functions..." -ForegroundColor Green
cargo bloat --release --bin tagio-gui-eframe -n 50

# Analyze for unused features
Write-Host "`nChecking for potential unused features..." -ForegroundColor Green
try {
    $null = cargo unused-features --help
    cargo unused-features
} catch {
    Write-Host "cargo-unused-features not found. You can install it with: cargo install cargo-unused-features" -ForegroundColor Yellow
}

Write-Host "`nAnalysis complete!" -ForegroundColor Green 