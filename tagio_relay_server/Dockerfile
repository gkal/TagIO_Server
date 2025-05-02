FROM rust:1.76-slim as builder

WORKDIR /app

# Copy Cargo manifest files
COPY Cargo.toml .

# Create a dummy src/main.rs to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo 'pub mod constants { pub const DEFAULT_BIND_ADDRESS: &str = ""; }' > src/constants.rs && \
    echo 'pub mod messages { pub enum MessageType { AuthFailure = 2, ClientRegistered = 3, ConnectionRequest = 4, ConnectionInfo = 5 } }' > src/messages.rs && \
    echo 'pub mod server { pub struct RelayServer; impl RelayServer { pub fn new(_: Option<String>, _: Option<String>) -> Self { Self } pub async fn run(&self, _: &str) -> anyhow::Result<()> { Ok(()) } } }' > src/server.rs && \
    cargo build --release

# Copy actual source code
COPY src ./src/

# Build the actual binary
RUN touch src/main.rs && cargo build --release

# Create a minimal runtime image
FROM debian:bullseye-slim

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/tagio_relay_server /app/tagio_relay_server

# Expose ports
EXPOSE 443 8080

# Set the entrypoint
ENTRYPOINT ["/app/tagio_relay_server"] 