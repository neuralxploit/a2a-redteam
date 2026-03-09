#!/bin/bash
# Setup persistent Cloudflare tunnel for the target app

TUNNEL_NAME="${CLOUDFLARE_TUNNEL_NAME:-orion-target-app}"
CONFIG_FILE="$HOME/.cloudflared/config.yml"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  🌐 Cloudflare Tunnel Setup                                     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if cloudflared is installed
if ! command -v cloudflared &> /dev/null; then
    echo "❌ cloudflared is not installed!"
    echo ""
    echo "Install it with:"
    echo "  brew install cloudflared"
    echo ""
    exit 1
fi

# Login to Cloudflare (if not already logged in)
echo "1️⃣  Logging into Cloudflare..."
echo ""
if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
    cloudflared tunnel login
    if [ $? -ne 0 ]; then
        echo "❌ Failed to login to Cloudflare"
        exit 1
    fi
else
    echo "✅ Already logged in"
fi

echo ""
echo "2️⃣  Creating tunnel: $TUNNEL_NAME"
echo ""

# Create tunnel (will skip if exists)
cloudflared tunnel create $TUNNEL_NAME 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Tunnel created successfully!"
else
    echo "ℹ️  Tunnel already exists, using existing tunnel"
fi

# Get tunnel ID
TUNNEL_ID=$(cloudflared tunnel list | grep $TUNNEL_NAME | awk '{print $1}')
if [ -z "$TUNNEL_ID" ]; then
    echo "❌ Failed to get tunnel ID"
    exit 1
fi

echo ""
echo "3️⃣  Configuring tunnel..."
echo ""

# Create config directory
mkdir -p "$HOME/.cloudflared"

# Create/update config file
cat > "$CONFIG_FILE" << EOF
tunnel: $TUNNEL_ID
credentials-file: $HOME/.cloudflared/$TUNNEL_ID.json

ingress:
  - hostname: $TUNNEL_NAME.cfargotunnel.com
    service: http://localhost:8000
  - service: http_status:404
EOF

echo "✅ Config file created at: $CONFIG_FILE"

echo ""
echo "4️⃣  Creating DNS record..."
echo ""

# Create DNS record
cloudflared tunnel route dns $TUNNEL_NAME $TUNNEL_NAME.cfargotunnel.com 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ DNS record created!"
else
    echo "ℹ️  DNS record might already exist"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ Setup Complete!                                             ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Tunnel Name: $TUNNEL_NAME"
echo "║  Public URL:  https://$TUNNEL_NAME.cfargotunnel.com"
echo "║"
echo "║  This URL will stay the same every time you run ./run.sh"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
