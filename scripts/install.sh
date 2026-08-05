#!/bin/bash
# Anvil Mesh Node — One-liner installer
#
# Secure install (pinned to a release tag):
#   curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/v1.1.1/scripts/install.sh | sudo bash
#
# Latest (follows main — less secure, but always current):
#   curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/main/scripts/install.sh | sudo bash
#
# Supply chain security:
#   - Script is served from GitHub (not VPS) — immutable at tagged commits
#   - Binary is downloaded from GitHub Releases
#   - SHA256 checksum is verified against checksums.txt from the same release
#   - All source code is public at https://github.com/BSVanon/Anvil
#
# Requirements: Linux (amd64 or arm64), root/sudo, ~50MB disk

set -euo pipefail

ANVIL_VERSION="${ANVIL_VERSION:-latest}"
ANVIL_REPO="BSVanon/Anvil"
INSTALL_DIR="/opt/anvil"
SEED_PEER="${ANVIL_SEED:-wss://anvil.sendbsv.com/mesh}"
NODE_NAME="${ANVIL_NAME:-}"
API_PORT="9333"
CONFIG_FILE="/etc/anvil/node-a.toml"

# ── Colors & formatting ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

pause_msg() {
  echo ""
  echo -e "  ${DIM}press enter to continue...${NC}"
  read -r < /dev/tty
}

# ── Detect architecture ──
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  BINARY="anvil-linux-amd64" ;;
  aarch64) BINARY="anvil-linux-arm64" ;;
  *)
    echo -e "${RED}Error: unsupported architecture $ARCH (need x86_64 or aarch64)${NC}"
    exit 1
    ;;
esac

# ── Check root ──
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}Error: run with sudo or as root${NC}"
  echo "  curl -fsSL https://raw.githubusercontent.com/${ANVIL_REPO}/main/scripts/install.sh | sudo bash"
  exit 1
fi

# ── Check sha256sum available ──
if ! command -v sha256sum &>/dev/null; then
  echo -e "${RED}Error: sha256sum required for binary verification${NC}"
  exit 1
fi

# ══════════════════════════════════════════════════════════════
# Upgrade-mode detection
#
# If a config file already exists, this is an upgrade rather than a
# fresh install. We MUST NOT run the deploy step (it would regenerate
# the operator's identity WIF, destroying access to their funded
# wallet). Instead we run a streamlined download → verify → swap →
# restart → doctor flow.
#
# Why this branch lives here: third-party operators on v2.2.x or
# earlier hit a chicken-and-egg with `sudo anvil upgrade` — their
# old upgrade.go binary predates the v2.3.0+ auto-doctor step, so
# upgrading from those versions to v3 leaves the SQLite/PrivateTmp +
# systemd-hook gaps unresolved. This install.sh branch invokes the
# NEW v3 binary's `anvil doctor --yes` post-swap, which contains the
# auto-migrate + PrivateTmp + ExecStartPre self-heal logic. So a
# single one-liner works for any starting version:
#
#   curl -fsSL https://anvil.sendbsv.com/install | sudo bash
#
# ══════════════════════════════════════════════════════════════

if [ -f "$CONFIG_FILE" ]; then
  echo ""
  echo -e "  ${BOLD}━━━ Anvil Upgrade ━━━${NC}"
  echo ""
  echo -e "  Detected existing installation at ${DIM}${CONFIG_FILE}${NC}"
  echo -e "  Running upgrade flow (preserves identity, config, data)."
  echo ""

  # ── Detect existing services ──
  RUNNING_SERVICES=()
  for svc in anvil-a anvil-b; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
      RUNNING_SERVICES+=("$svc")
    fi
  done

  CURRENT_VERSION=""
  if [ -x "${INSTALL_DIR}/anvil" ]; then
    CURRENT_VERSION=$("${INSTALL_DIR}/anvil" --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
  fi

  TARGET_VERSION="$ANVIL_VERSION"
  echo -e "  ${DIM}current:  ${CURRENT_VERSION:-unknown}${NC}"
  echo -e "  ${DIM}target:   ${TARGET_VERSION}${NC}"
  echo -e "  ${DIM}services: ${RUNNING_SERVICES[*]:-none running}${NC}"
  echo ""

  # ── Download binary + checksums.txt ──
  UPGRADE_TMP=$(mktemp /tmp/anvil-upgrade.XXXXXX)
  UPGRADE_CHK=$(mktemp /tmp/anvil-upgrade-checksums.XXXXXX)
  trap "rm -f $UPGRADE_TMP $UPGRADE_CHK" EXIT

  if [ "$TARGET_VERSION" = "latest" ]; then
    UPGRADE_BASE="https://github.com/${ANVIL_REPO}/releases/latest/download"
  else
    UPGRADE_BASE="https://github.com/${ANVIL_REPO}/releases/download/${TARGET_VERSION}"
  fi

  echo -e "  ${DIM}[1/5] Downloading ${BINARY}...${NC}"
  if command -v curl &>/dev/null; then
    curl -fsSL "${UPGRADE_BASE}/${BINARY}" -o "$UPGRADE_TMP"
    curl -fsSL "${UPGRADE_BASE}/checksums.txt" -o "$UPGRADE_CHK"
  elif command -v wget &>/dev/null; then
    wget -q "${UPGRADE_BASE}/${BINARY}" -O "$UPGRADE_TMP"
    wget -q "${UPGRADE_BASE}/checksums.txt" -O "$UPGRADE_CHK"
  else
    echo -e "  ${RED}Error: curl or wget required${NC}"
    exit 1
  fi

  # ── SHA256 verify ──
  EXPECTED_HASH=$(grep "${BINARY}" "$UPGRADE_CHK" | awk '{print $1}')
  if [ -z "$EXPECTED_HASH" ]; then
    echo -e "  ${RED}Error: no checksum for ${BINARY} in release${NC}"
    exit 1
  fi
  ACTUAL_HASH=$(sha256sum "$UPGRADE_TMP" | awk '{print $1}')
  if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    echo -e "  ${RED}Error: SHA256 mismatch — binary may be tampered with${NC}"
    echo -e "  ${RED}  expected: ${EXPECTED_HASH}${NC}"
    echo -e "  ${RED}  got:      ${ACTUAL_HASH}${NC}"
    exit 1
  fi
  chmod 755 "$UPGRADE_TMP"
  echo -e "  ${GREEN}✓${NC} SHA256 verified (${DIM}${ACTUAL_HASH:0:16}...${NC})"

  # ── Stop services ──
  echo -e "  ${DIM}[2/5] Stopping services...${NC}"
  for svc in "${RUNNING_SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
  done
  sleep 1

  # ── Backup + atomic swap ──
  echo -e "  ${DIM}[3/5] Installing binary (atomic swap)...${NC}"
  if [ -x "${INSTALL_DIR}/anvil" ]; then
    cp "${INSTALL_DIR}/anvil" "${INSTALL_DIR}/anvil.prev" 2>/dev/null || true
  fi
  cp "$UPGRADE_TMP" "${INSTALL_DIR}/anvil.new"
  chmod 755 "${INSTALL_DIR}/anvil.new"
  mv "${INSTALL_DIR}/anvil.new" "${INSTALL_DIR}/anvil"
  # Refresh /usr/local/bin/anvil symlink
  ln -sf "${INSTALL_DIR}/anvil" /usr/local/bin/anvil
  NEW_VERSION=$("${INSTALL_DIR}/anvil" --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
  echo -e "  ${GREEN}✓${NC} Installed ${NEW_VERSION}"

  # ── Restart services ──
  echo -e "  ${DIM}[4/5] Restarting services...${NC}"
  for svc in "${RUNNING_SERVICES[@]}"; do
    systemctl start "$svc" 2>/dev/null || true
  done
  sleep 5

  # ── Run NEW binary's doctor for full self-heal ──
  # This is the load-bearing step for any v2.2.x or earlier operator:
  # the v3+ doctor auto-creates the PrivateTmp drop-in for SQLite,
  # wipes-and-rebuilds stale headers, and verifies the service comes
  # back up clean. Without this step, third-party operators on old
  # versions end up half-upgraded.
  echo -e "  ${DIM}[5/5] Running post-upgrade self-heal (anvil doctor --yes)...${NC}"
  echo ""
  "${INSTALL_DIR}/anvil" doctor --yes || {
    echo ""
    echo -e "  ${YELLOW}WARNING: doctor reported unresolved issues — see output above${NC}"
    echo -e "  ${DIM}Binary upgrade succeeded; manual follow-up may be needed.${NC}"
  }

  echo ""
  echo -e "  ${GREEN}${BOLD}Upgrade complete: ${CURRENT_VERSION:-unknown} → ${NEW_VERSION}${NC}"
  echo ""
  exit 0
fi

# ══════════════════════════════════════════════════════════════
# SCREEN 1: Welcome (fresh install path)
# ══════════════════════════════════════════════════════════════

clear
echo ""
echo ""
cat << 'BANNER'
       ╔═══════════════════════════════════════════════════════╗
       ║                                                       ║
       ║              ▄▀█ █▄░█ █░█ █ █░░                      ║
       ║              █▀█ █░▀█ ▀▄▀ █ █▄▄                      ║
       ║                                                       ║
       ║          BSV SPV Node · x402 Payments · Mesh          ║
       ║                                                       ║
       ╚═══════════════════════════════════════════════════════╝
BANNER
echo ""
echo ""
echo -e "  Welcome. This script will turn this machine into an"
echo -e "  Anvil mesh node in about 3 minutes."
echo ""
echo -e "  ${DIM}What happens next:${NC}"
echo ""
echo -e "    ${GREEN}▸${NC} Download the Anvil binary (with checksum verification)"
echo -e "    ${GREEN}▸${NC} Generate your node's unique identity"
echo -e "    ${GREEN}▸${NC} Sync BSV block headers"
echo -e "    ${GREEN}▸${NC} Show your wallet address to fund"
echo ""
echo -e "  ${DIM}You will need about 1,000,000 satoshis (~\$0.50 USD)${NC}"
echo -e "  ${DIM}to fund the node's wallet. Have a BSV wallet ready.${NC}"
echo ""

pause_msg

# ══════════════════════════════════════════════════════════════
# SCREEN 2: Download + Verify + Install
# ══════════════════════════════════════════════════════════════

clear
echo ""
echo ""
echo -e "  ${BOLD}━━━ STEP 1 of 4: Installing Anvil ━━━${NC}"
echo ""
echo ""
echo -e "  ${DIM}Downloading binary for ${ARCH}...${NC}"
echo ""

TMPBIN=$(mktemp /tmp/anvil-install.XXXXXX)
TMPCHK=$(mktemp /tmp/anvil-checksums.XXXXXX)
trap "rm -f $TMPBIN $TMPCHK" EXIT

# Allow local binary for testing: ANVIL_LOCAL_BINARY=/path/to/anvil
if [ -n "${ANVIL_LOCAL_BINARY:-}" ] && [ -f "$ANVIL_LOCAL_BINARY" ]; then
  cp "$ANVIL_LOCAL_BINARY" "$TMPBIN"
  echo -e "    ${DIM}(using local binary: ${ANVIL_LOCAL_BINARY} — checksum skip)${NC}"
else
  if [ "$ANVIL_VERSION" = "latest" ]; then
    RELEASE_BASE="https://github.com/${ANVIL_REPO}/releases/latest/download"
  else
    RELEASE_BASE="https://github.com/${ANVIL_REPO}/releases/download/${ANVIL_VERSION}"
  fi

  DOWNLOAD_URL="${RELEASE_BASE}/${BINARY}"
  CHECKSUM_URL="${RELEASE_BASE}/checksums.txt"

  if command -v curl &>/dev/null; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TMPBIN"
    curl -fsSL "$CHECKSUM_URL" -o "$TMPCHK"
  elif command -v wget &>/dev/null; then
    wget -q "$DOWNLOAD_URL" -O "$TMPBIN"
    wget -q "$CHECKSUM_URL" -O "$TMPCHK"
  else
    echo -e "  ${RED}Error: curl or wget required${NC}"
    exit 1
  fi

  # ── Verify SHA256 checksum ──
  EXPECTED=$(grep "${BINARY}" "$TMPCHK" | awk '{print $1}')
  if [ -z "$EXPECTED" ]; then
    echo -e "  ${RED}Error: no checksum found for ${BINARY} in checksums.txt${NC}"
    echo -e "  ${DIM}This could mean the release is incomplete or tampered with.${NC}"
    exit 1
  fi

  ACTUAL=$(sha256sum "$TMPBIN" | awk '{print $1}')
  if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo -e "  ${RED}Error: SHA256 checksum mismatch!${NC}"
    echo -e "  ${RED}  Expected: ${EXPECTED}${NC}"
    echo -e "  ${RED}  Got:      ${ACTUAL}${NC}"
    echo ""
    echo -e "  ${RED}The binary may have been tampered with. Aborting.${NC}"
    exit 1
  fi

  echo -e "    ${GREEN}✓${NC} SHA256 verified: ${DIM}${ACTUAL:0:16}...${NC}"
fi
chmod 755 "$TMPBIN"

# Stop any running instance before overwriting
systemctl stop anvil-a 2>/dev/null || true
systemctl stop anvil-b 2>/dev/null || true
sleep 1

mkdir -p "$INSTALL_DIR"
cp "$TMPBIN" "${INSTALL_DIR}/anvil"
chmod 755 "${INSTALL_DIR}/anvil"

echo -e "    ${GREEN}✓${NC} Binary downloaded and installed"
echo ""

# ══════════════════════════════════════════════════════════════
# SCREEN 2b: Deploy (identity, config, systemd)
# ══════════════════════════════════════════════════════════════

echo -e "  ${DIM}Generating identity and configuring services...${NC}"
echo ""

DEPLOY_ARGS="--nodes a --skip-health"
if [ -n "$SEED_PEER" ]; then
  DEPLOY_ARGS="$DEPLOY_ARGS --seed $SEED_PEER"
fi
if [ -n "$NODE_NAME" ]; then
  DEPLOY_ARGS="$DEPLOY_ARGS --name $NODE_NAME"
fi

"$TMPBIN" deploy $DEPLOY_ARGS >/dev/null 2>&1

echo -e "    ${GREEN}✓${NC} Identity generated"
echo -e "    ${GREEN}✓${NC} Config written to /etc/anvil/"
echo -e "    ${GREEN}✓${NC} Systemd service created and started"
echo ""
echo ""
echo -e "  ${GREEN}${BOLD}  Installation complete.${NC}"
echo ""

sleep 2

# ══════════════════════════════════════════════════════════════
# SCREEN 3: Identity — SAVE THIS
# ══════════════════════════════════════════════════════════════

# Get node info
NODE_INFO=$("${INSTALL_DIR}/anvil" info -config "$CONFIG_FILE" -json 2>/dev/null || echo "")

IDENTITY=""
WALLET_ADDR=""
AUTH_TOKEN=""

if [ -n "$NODE_INFO" ]; then
  IDENTITY=$(echo "$NODE_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('identity_key',''))" 2>/dev/null || echo "")
  WALLET_ADDR=$(echo "$NODE_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('address',''))" 2>/dev/null || echo "")
  AUTH_TOKEN=$(echo "$NODE_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('auth_token',''))" 2>/dev/null || echo "")
fi

clear
echo ""
echo ""
echo -e "  ${BOLD}━━━ STEP 2 of 4: Your Node Identity ━━━${NC}"
echo ""
echo ""
echo -e "  ${RED}${BOLD}  ╔════════════════════════════════════════════════════╗${NC}"
echo -e "  ${RED}${BOLD}  ║                                                    ║${NC}"
echo -e "  ${RED}${BOLD}  ║   WRITE THIS DOWN. YOUR PRIVATE KEY CANNOT BE      ║${NC}"
echo -e "  ${RED}${BOLD}  ║   RECOVERED IF YOU LOSE IT.                        ║${NC}"
echo -e "  ${RED}${BOLD}  ║                                                    ║${NC}"
echo -e "  ${RED}${BOLD}  ╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo ""
echo -e "  ${BOLD}Your private key (WIF) is stored in:${NC}"
echo ""
echo -e "    ${CYAN}/etc/anvil/node-a.env${NC}"
echo ""
echo -e "  ${BOLD}View it now and copy it somewhere safe:${NC}"
echo ""
echo -e "    ${CYAN}sudo cat /etc/anvil/node-a.env${NC}"
echo ""
echo ""
if [ -n "$IDENTITY" ]; then
  echo -e "  ${DIM}Your node's public identity:${NC}"
  echo -e "    ${IDENTITY}"
  echo ""
fi

pause_msg

# ══════════════════════════════════════════════════════════════
# SCREEN 4: Fund your node
# ══════════════════════════════════════════════════════════════

clear
echo ""
echo ""
echo -e "  ${BOLD}━━━ STEP 3 of 4: Fund Your Node ━━━${NC}"
echo ""
echo ""
echo -e "  Your node needs BSV to operate. Send ${BOLD}1,000,000 satoshis${NC}"
echo -e "  (about \$0.50 USD) to this address:"
echo ""
echo ""

if [ -n "$WALLET_ADDR" ]; then
  echo -e "       ┌──────────────────────────────────────────┐"
  echo -e "       │                                          │"
  echo -e "       │   ${GREEN}${BOLD}${WALLET_ADDR}${NC}   │"
  echo -e "       │                                          │"
  echo -e "       └──────────────────────────────────────────┘"

  # Try to generate a QR code if qrencode is available
  if command -v qrencode &>/dev/null; then
    echo ""
    echo -e "  ${DIM}Scan with your wallet:${NC}"
    echo ""
    qrencode -t ANSIUTF8 -m 2 "bitcoin:${WALLET_ADDR}?sv&amount=0.01" 2>/dev/null | while IFS= read -r line; do
      echo "       $line"
    done
  else
    # Try to install qrencode silently
    apt-get install -y qrencode >/dev/null 2>&1 || true
    if command -v qrencode &>/dev/null; then
      echo ""
      echo -e "  ${DIM}Scan with your wallet:${NC}"
      echo ""
      qrencode -t ANSIUTF8 -m 2 "bitcoin:${WALLET_ADDR}?sv&amount=0.01" 2>/dev/null | while IFS= read -r line; do
        echo "       $line"
      done
    fi
  fi
else
  echo -e "  ${RED}Could not derive address. Run manually:${NC}"
  echo -e "    ${CYAN}anvil info -config ${CONFIG_FILE}${NC}"
fi

echo ""
echo ""
echo -e "  ${YELLOW}${BOLD}After sending, wait for 1 confirmation.${NC}"
echo ""
echo -e "  ${DIM}While you wait, your node is syncing block headers${NC}"
echo -e "  ${DIM}in the background. We'll show you the progress next.${NC}"
echo ""

pause_msg

# ══════════════════════════════════════════════════════════════
# SCREEN 5: Header sync progress
# ══════════════════════════════════════════════════════════════

clear
echo ""
echo ""
echo -e "  ${BOLD}━━━ STEP 4 of 4: Syncing Block Headers ━━━${NC}"
echo ""
echo ""
echo -e "  ${DIM}Your node is downloading BSV block headers (80 bytes each).${NC}"
echo -e "  ${DIM}This is NOT the full blockchain — just headers for SPV${NC}"
echo -e "  ${DIM}verification. Usually takes 1-3 minutes.${NC}"
echo ""
echo ""

LAST_HEIGHT=0
PREV_HEIGHT=0
STALL_COUNT=0
SYNCED=false
MAX_WAIT=300
WAITED=0

while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  STATUS=$(curl -s "http://127.0.0.1:${API_PORT}/status" 2>/dev/null || echo "")

  if [ -n "$STATUS" ]; then
    HEIGHT=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('headers',{}).get('height',0))" 2>/dev/null || echo "0")

    if [ "$HEIGHT" -gt 0 ]; then
      if [ "$HEIGHT" = "$PREV_HEIGHT" ] && [ "$HEIGHT" -gt 900000 ]; then
        STALL_COUNT=$((STALL_COUNT + 1))
        if [ "$STALL_COUNT" -ge 3 ]; then
          SYNCED=true
          LAST_HEIGHT=$HEIGHT
          break
        fi
      else
        STALL_COUNT=0
      fi
      PREV_HEIGHT=$HEIGHT
      LAST_HEIGHT=$HEIGHT

      APPROX_TIP=942000
      [ "$HEIGHT" -gt "$APPROX_TIP" ] && APPROX_TIP=$HEIGHT
      PCT=$((HEIGHT * 100 / APPROX_TIP))
      BAR_WIDTH=40
      FILLED=$((PCT * BAR_WIDTH / 100))
      EMPTY=$((BAR_WIDTH - FILLED))
      BAR=""
      SPACE=""
      for ((i=0; i<FILLED; i++)); do BAR="${BAR}█"; done
      for ((i=0; i<EMPTY; i++)); do SPACE="${SPACE}░"; done

      printf "\r    ${CYAN}${BAR}${SPACE}${NC}  ${BOLD}%3d%%${NC}  block %s  " "$PCT" "$HEIGHT"
    fi
  else
    printf "\r    ${DIM}⏳  Starting up...${NC}                                        "
  fi

  sleep 2
  WAITED=$((WAITED + 2))
done

echo ""

if [ "$SYNCED" = true ]; then
  echo ""
  echo -e "    ${GREEN}✓${NC} Synced to block ${BOLD}${LAST_HEIGHT}${NC} — your node is at the chain tip."
else
  echo ""
  echo -e "    ${YELLOW}⏳${NC} Still syncing (block ${LAST_HEIGHT}). Running in background."
  echo -e "    ${DIM}   Check: curl -s http://localhost:${API_PORT}/status${NC}"
fi

sleep 2

# ══════════════════════════════════════════════════════════════
# SCREEN 6: Final — claim funds + you're live
# ══════════════════════════════════════════════════════════════

clear
echo ""
echo ""
cat << 'DONE_ART'

       ╔═══════════════════════════════════════════════════════╗
       ║                                                       ║
       ║              ◆  YOUR NODE IS LIVE  ◆                  ║
       ║                                                       ║
       ╚═══════════════════════════════════════════════════════╝

DONE_ART

echo ""
echo -e "  Headers are synced. Your node is connected to the Anvil"
echo -e "  mesh and peering with other nodes automatically."
echo ""
echo ""

if [ -n "$WALLET_ADDR" ] && [ -n "$AUTH_TOKEN" ]; then
  echo -e "  ${BOLD}LAST STEP: Claim your funds${NC}"
  echo ""
  echo -e "  ${DIM}If you've already sent BSV to your address and it has${NC}"
  echo -e "  ${DIM}at least 1 confirmation, run this command to import${NC}"
  echo -e "  ${DIM}the funds into your node's wallet:${NC}"
  echo ""
  echo -e "    ${CYAN}curl -X POST http://localhost:${API_PORT}/wallet/scan \\${NC}"
  echo -e "    ${CYAN}  -H \"Authorization: Bearer ${AUTH_TOKEN}\"${NC}"
  echo ""
  echo -e "  ${DIM}Run this any time you send more funds to your node.${NC}"
  echo ""
  echo ""
fi

echo -e "  ${DIM}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${BOLD}YOUR NODE${NC}"
echo ""
if [ -n "$WALLET_ADDR" ]; then
  echo -e "    Address:     ${GREEN}${WALLET_ADDR}${NC}"
fi
if [ -n "$IDENTITY" ]; then
  echo -e "    Identity:    ${DIM}${IDENTITY}${NC}"
fi
echo -e "    API:         ${CYAN}http://localhost:${API_PORT}/status${NC}"
echo -e "    Config:      /etc/anvil/node-a.toml"
echo -e "    Private key: /etc/anvil/node-a.env"
echo ""
echo -e "  ${DIM}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${BOLD}USEFUL COMMANDS${NC}"
echo ""
echo -e "    ${YELLOW}${BOLD}anvil help${NC}                                 ${YELLOW}All commands${NC}"
echo -e "    ${CYAN}sudo anvil info${NC}                            Node info"
echo -e "    ${CYAN}sudo anvil doctor${NC}                          Diagnostics"
echo -e "    ${CYAN}sudo journalctl -u anvil-a -f${NC}              Live logs"
echo -e "    ${CYAN}sudo systemctl restart anvil-a${NC}             Restart"
echo ""
echo -e "  ${DIM}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${BOLD}RENAME YOUR NODE${NC}"
echo ""
echo -e "  ${DIM}Your node was auto-named from its identity key.${NC}"
echo -e "  ${DIM}To give it a custom name:${NC}"
echo ""
echo -e "    ${CYAN}sudo sed -i 's|name = \"anvil-.*\"|name = \"my-node-name\"|' ${CONFIG_FILE}${NC}"
echo -e "    ${CYAN}sudo systemctl restart anvil-a${NC}"
echo ""
echo -e "  ${DIM}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${RED}${BOLD}  OPEN YOUR FIREWALL${NC}"
echo ""
echo -e "  ${RED}  Ports 8333 (mesh) and 9333 (API) MUST be open for${NC}"
echo -e "  ${RED}  inbound connections or your node cannot join the mesh.${NC}"
echo ""
echo -e "    ${CYAN}sudo ufw allow 8333/tcp${NC}"
echo -e "    ${CYAN}sudo ufw allow 9333/tcp${NC}"
echo ""
echo -e "  ${DIM}─────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${BOLD}YOUR EXPLORER${NC}"
echo ""
echo -e "  ${DIM}Visit your node's explorer in a browser:${NC}"
echo ""
echo -e "    ${CYAN}http://$(curl -4 -s ifconfig.me 2>/dev/null || echo '<your-ip>'):${API_PORT}/explorer${NC}"
echo ""
echo -e "  ${DIM}To log in and manage your wallet from the Explorer:${NC}"
echo ""
echo -e "    ${CYAN}sudo anvil token${NC}    ${DIM}→ copy the token → paste in Explorer → Node Login${NC}"
echo ""
echo ""
echo -e "  ${GREEN}${BOLD}Welcome to the Anvil mesh. ◆${NC}"
echo ""
echo ""
