#!/usr/bin/env bash
# Launch a 2-node Anvil mesh locally for development.
# Each node gets its own data dir, ports, and identity.
#
# Usage: ./foundry/launch-local.sh
#
# Prerequisites:
#   - Anvil binary built: go build -o anvil ./cmd/anvil
#   - Two WIF keys (generated below if not set)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/anvil"

if [ ! -f "$BINARY" ]; then
    echo "Building anvil..."
    (cd "$PROJECT_DIR" && go build -o anvil ./cmd/anvil)
fi

# Create temp data dirs
DATA_A=$(mktemp -d /tmp/<node-a>-XXXXXX)
DATA_B=$(mktemp -d /tmp/<node-b>-XXXXXX)
trap "rm -rf $DATA_A $DATA_B; echo 'Cleaned up temp dirs'" EXIT

# Generate WIF keys if not provided
if [ -z "${WIF_A:-}" ]; then
    echo "No WIF_A set — generating ephemeral key for Node A"
    WIF_A="***REMOVED-KEY***"
fi
if [ -z "${WIF_B:-}" ]; then
    echo "No WIF_B set — generating ephemeral key for Node B"
    WIF_B="***REMOVED-KEY***"
fi

echo "=== Anvil Local Mesh ==="
echo "  Node A: mesh=:8333  api=:9333  data=$DATA_A"
echo "  Node B: mesh=:8334  api=:9334  data=$DATA_B"
echo ""

# Write temp configs with local data dirs
cat > "$DATA_A/config.toml" <<EOF
[node]
name = "local-a"
data_dir = "$DATA_A"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"

[mesh]
seeds = []

[bsv]
nodes = ["seed.bitcoinsv.io:8333"]

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = false

[overlay]
enabled = true
topics = ["anvil:local"]

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

[api]
rate_limit = 0
payment_satoshis = 10

[api.app_payments]
allow_passthrough = true
allow_split = true
allow_token_gating = true
max_app_price_sats = 10000
EOF

cat > "$DATA_B/config.toml" <<EOF
[node]
name = "local-b"
data_dir = "$DATA_B"
listen = "0.0.0.0:8334"
api_listen = "0.0.0.0:9334"

[mesh]
seeds = ["ws://127.0.0.1:8333"]

[bsv]
nodes = ["seed.bitcoinsv.io:8333"]

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = false

[overlay]
enabled = true
topics = ["anvil:local"]

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

[api]
rate_limit = 0
payment_satoshis = 0

[api.app_payments]
allow_passthrough = true
allow_split = true
allow_token_gating = true
max_app_price_sats = 10000
EOF

echo "Starting Node A..."
ANVIL_IDENTITY_WIF="$WIF_A" "$BINARY" -config "$DATA_A/config.toml" &
PID_A=$!

# Give A time to bind its mesh port
sleep 2

echo "Starting Node B (seeds to A)..."
ANVIL_IDENTITY_WIF="$WIF_B" "$BINARY" -config "$DATA_B/config.toml" &
PID_B=$!

echo ""
echo "Both nodes running. Press Ctrl+C to stop."
echo "  Node A API: http://localhost:9333/status"
echo "  Node B API: http://localhost:9334/status"
echo "  Node A x402: http://localhost:9333/.well-known/x402"
echo ""

wait
