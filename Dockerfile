FROM rust:1.75-slim as builder

WORKDIR /app

# Copy only the necessary files for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Create minimal src files to compile dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/tagio_relay_server.rs && \
    echo "pub fn dummy() {}" > src/lib.rs

# Build dependencies - this will be cached
RUN cargo build --release --bin tagio_relay_server --no-default-features --features server

# Remove the dummy source code
RUN rm -rf src

# Copy actual source code
COPY src/ src/

# Build the application with server features only
RUN cargo build --release --bin tagio_relay_server --no-default-features --features server

# Use a smaller runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies
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