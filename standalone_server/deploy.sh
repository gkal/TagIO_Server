#!/bin/bash
# TagIO Relay Server deployment script
# For Render.com and similar cloud platforms

# Build the release version
echo "Building TagIO Relay Server..."
cargo build --release

# Prepare the deployment directory
DEPLOY_DIR="deploy"
mkdir -p $DEPLOY_DIR

# Copy the binary and configuration
echo "Preparing deployment package..."
cp target/release/tagio_relay_server $DEPLOY_DIR/

# Create a simple run script
cat > $DEPLOY_DIR/run.sh << 'EOL'
#!/bin/bash
PORT=${PORT:-443}
PUBLIC_IP=${PUBLIC_IP:-""}
AUTH_SECRET=${AUTH_SECRET:-""}

ARGS=""
if [ ! -z "$PUBLIC_IP" ]; then
  ARGS="$ARGS --public-ip $PUBLIC_IP"
fi
if [ ! -z "$AUTH_SECRET" ]; then
  ARGS="$ARGS --auth $AUTH_SECRET"
fi

echo "Starting TagIO Relay Server on port $PORT"
./tagio_relay_server --bind 0.0.0.0:$PORT $ARGS
EOL

# Make the run script executable
chmod +x $DEPLOY_DIR/run.sh

echo "Deployment package created in $DEPLOY_DIR directory"
echo "Upload these files to your cloud provider"
echo "Set the following environment variables if desired:"
echo "  - PORT: Server port (default: 443)"
echo "  - PUBLIC_IP: Override public IP detection"
echo "  - AUTH_SECRET: Custom authentication secret" 