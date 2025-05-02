FROM rust:1.75-slim as builder

WORKDIR /app

# Install only essential build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only the necessary files for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Create minimal src files to compile dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/tagio_relay_server.rs && \
    echo "pub fn dummy() {}" > src/lib.rs

# Build dependencies - this will be cached
# Only build the server with NO_ATK, NO_GTK, etc. environment variables
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    PKG_CONFIG_ALLOW_CROSS=1 \
    ATK_NO_PKG_CONFIG=1 \
    GTK_NO_PKG_CONFIG=1 \
    GDK_NO_PKG_CONFIG=1 \
    PANGO_NO_PKG_CONFIG=1 \
    CAIRO_NO_PKG_CONFIG=1 \
    cargo build --release --bin tagio_relay_server --no-default-features --features server

# Remove the dummy source code
RUN rm -rf src

# Copy actual source code
COPY src/ src/

# Build the application with server features only
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    PKG_CONFIG_ALLOW_CROSS=1 \
    ATK_NO_PKG_CONFIG=1 \
    GTK_NO_PKG_CONFIG=1 \
    GDK_NO_PKG_CONFIG=1 \
    PANGO_NO_PKG_CONFIG=1 \
    CAIRO_NO_PKG_CONFIG=1 \
    cargo build --release --bin tagio_relay_server --no-default-features --features server

# Use a minimal Debian slim image for runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install only necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the server binary
COPY --from=builder /app/target/release/tagio_relay_server .

# Expose the necessary ports
EXPOSE 443
EXPOSE 8080

# Set environment variables
ENV RUST_LOG=info
ENV PUBLIC_IP=automatic
ENV PORT=443

# Run the server
CMD ["./tagio_relay_server"] 