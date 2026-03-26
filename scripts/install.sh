#!/bin/bash
# Anvil Mesh Node — One-liner installer
# Usage: curl -fsSL https://anvil.sendbsv.com/install | sudo bash
#
# What this does:
#   1. Downloads the Anvil binary for your architecture
#   2. Generates a fresh identity (WIF + public key)
#   3. Creates config, data dirs, systemd service
#   4. Connects to the Anvil mesh
#   5. Starts syncing BSV headers
#
# Requirements: Linux (amd64 or arm64), root/sudo, ~50MB disk

set -euo pipefail

ANVIL_VERSION="${ANVIL_VERSION:-latest}"
ANVIL_REPO="BSVanon/Anvil"
INSTALL_DIR="/opt/anvil"
SEED_PEER="${ANVIL_SEED:-wss://anvil.sendbsv.com:8333}"
NODE_NAME="${ANVIL_NAME:-}"

# ── Detect architecture ──
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  BINARY="anvil-linux-amd64" ;;
  aarch64) BINARY="anvil-linux-arm64" ;;
  *)
    echo "Error: unsupported architecture $ARCH (need x86_64 or aarch64)"
    exit 1
    ;;
esac

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║        Anvil Mesh Node Setup         ║"
echo "  ║   BSV SPV · x402 Payments · Gossip   ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Check root ──
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: run with sudo or as root"
  echo "  curl -fsSL https://anvil.sendbsv.com/install | sudo bash"
  exit 1
fi

# ── Download binary ──
echo "[1/3] Downloading Anvil ($ARCH)..."

if [ "$ANVIL_VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/${ANVIL_REPO}/releases/latest/download/${BINARY}"
else
  DOWNLOAD_URL="https://github.com/${ANVIL_REPO}/releases/download/${ANVIL_VERSION}/${BINARY}"
fi

mkdir -p "$INSTALL_DIR"
if command -v curl &>/dev/null; then
  curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/anvil"
elif command -v wget &>/dev/null; then
  wget -q "$DOWNLOAD_URL" -O "${INSTALL_DIR}/anvil"
else
  echo "Error: curl or wget required"
  exit 1
fi
chmod 755 "${INSTALL_DIR}/anvil"
echo "  ✓ Binary installed: ${INSTALL_DIR}/anvil"

# ── Deploy (generates identity, config, systemd, starts service) ──
echo ""
echo "[2/3] Configuring node..."

DEPLOY_ARGS="--nodes a"
if [ -n "$SEED_PEER" ]; then
  DEPLOY_ARGS="$DEPLOY_ARGS --seed $SEED_PEER"
fi
if [ -n "$NODE_NAME" ]; then
  DEPLOY_ARGS="$DEPLOY_ARGS --name $NODE_NAME"
fi

"${INSTALL_DIR}/anvil" deploy $DEPLOY_ARGS

# ── Summary ──
echo ""
echo "[3/3] Node is running!"
echo ""
echo "  ┌──────────────────────────────────────┐"
echo "  │  Your Anvil node is live.             │"
echo "  │                                       │"
echo "  │  API:    http://localhost:9333/status  │"
echo "  │  Mesh:   ws://0.0.0.0:8333            │"
echo "  │  Config: /etc/anvil/node-a.toml       │"
echo "  │  Logs:   journalctl -u anvil-a -f     │"
echo "  │                                       │"
echo "  │  Auth token:                          │"

# Print the derived auth token
AUTH=$("${INSTALL_DIR}/anvil" token -config /etc/anvil/node-a.toml 2>/dev/null || echo "(run: anvil token -config /etc/anvil/node-a.toml)")
echo "  │  $AUTH"
echo "  │                                       │"
echo "  │  Next: open port 8333 + 9333 in your  │"
echo "  │  firewall for mesh peering and API.    │"
echo "  └──────────────────────────────────────┘"
echo ""
