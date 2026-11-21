package main

import (
	"strings"
	"testing"
)

// TestRenderGatewayUnit_HasCapabilitiesStandardDoesNot is the required
// golden test for each mode: a standard node's unit (renderUnit, used by
// deployNode) carries neither capability directive, while a gateway
// node's unit (renderGatewayUnit, used by deployGatewayNode) carries
// both, inserted right after LimitNOFILE=65536 — and is otherwise
// byte-for-byte the same unit.
func TestRenderGatewayUnit_HasCapabilitiesStandardDoesNot(t *testing.T) {
	standard := renderUnit("a", "/etc/anvil", "/var/lib/anvil", "/opt/anvil")
	gatewayUnit := renderGatewayUnit("a", "/etc/anvil", "/var/lib/anvil", "/opt/anvil")

	for _, want := range []string{gatewayCapabilityAmbient, gatewayCapabilityBoundingSet} {
		if strings.Contains(standard, want) {
			t.Errorf("standard unit unexpectedly contains %q", want)
		}
		if !strings.Contains(gatewayUnit, want) {
			t.Errorf("gateway unit is missing %q", want)
		}
	}

	want := `[Unit]
Description=Anvil Prime (seed node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anvil
Group=anvil
WorkingDirectory=/opt/anvil
# Pre-start self-heal: kill any orphan anvil processes that would hold
# LevelDB LOCK files and prevent this service instance from starting.
# Failure here must NOT block startup — runLocksOnly exits 0 even if
# the scan errors, so ExecStartPre never triggers a crash loop itself.
ExecStartPre=/opt/anvil/anvil doctor --locks-only
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
EnvironmentFile=/etc/anvil/node-a.env
Restart=on-failure
RestartSec=5
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=30
FinalKillSignal=SIGKILL
LimitNOFILE=65536

# Bind 80/443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/anvil
NoNewPrivileges=true
# Private /tmp: wallet-toolbox's SQLite needs a writable temp dir for
# sort/temp-table ops on larger wallet DBs. Without this, ProtectSystem=strict
# makes /tmp read-only and SQLite returns "disk I/O error: permission denied"
# during CreateAction calls. Discovered in v3.0.0 production (anvil-a 443MB
# wallet); fix shipped in v3.0.1.
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
	if gatewayUnit != want {
		t.Errorf("renderGatewayUnit golden mismatch.\ngot:\n%s\nwant:\n%s", gatewayUnit, want)
	}
}
