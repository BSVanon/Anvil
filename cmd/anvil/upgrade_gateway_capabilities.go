package main

// Keeps an existing gateway unit's systemd capabilities current across
// an upgrade. deployGatewayNode (deploy_gateway.go) writes the two
// capability directives into a fresh gateway unit via renderGatewayUnit;
// a unit installed before that existed never gets them just by
// upgrading the binary, since `anvil upgrade` never re-renders a unit
// file wholesale. ensureGatewayCapabilities closes that gap the same way
// ensureExecStartPreHook (upgrade.go) closes the equivalent gap for the
// orphan-cleanup hook: inspect every installed unit, patch only the ones
// that need it, leave the rest alone.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ensureGatewayCapabilities inspects every anvil-*.service unit file in
// the standard systemd location and, for each one whose referenced
// config file declares [gateway] enabled = true, ensures both
// capability directives are present — inserted immediately after
// gatewayCapabilityInsertAnchor, the same anchor renderGatewayUnit uses
// for a fresh deploy. A node with the gateway off, or one whose config
// can't be read, is left untouched. Returns the number of unit files
// modified.
func ensureGatewayCapabilities() int {
	return ensureGatewayCapabilitiesIn("/etc/systemd/system")
}

// ensureGatewayCapabilitiesIn is the testable core of
// ensureGatewayCapabilities, mirroring ensureExecStartPreHookIn's shape:
// tests pass a tempdir, production calls use /etc/systemd/system.
func ensureGatewayCapabilitiesIn(systemdDir string) int {
	entries, err := os.ReadDir(systemdDir)
	if err != nil {
		return 0
	}

	modified := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "anvil-") || !strings.HasSuffix(name, ".service") {
			continue
		}
		unitPath := filepath.Join(systemdDir, name)
		raw, err := os.ReadFile(unitPath)
		if err != nil {
			continue
		}
		content := string(raw)
		if !strings.Contains(content, "/opt/anvil/anvil") {
			continue // not one of our units
		}
		if strings.Contains(content, gatewayCapabilityAmbient) && strings.Contains(content, gatewayCapabilityBoundingSet) {
			continue // already present
		}
		if !unitReferencesGatewayConfig(content) {
			continue // the gateway is off for this node: nothing to add
		}
		newContent, ok := insertAfterAnchorOnce(content, gatewayCapabilityInsertAnchor, gatewayCapabilityInsertBlock)
		if !ok {
			fmt.Printf("    WARNING: %s: %q anchor not found exactly once — leaving this unit untouched\n", unitPath, gatewayCapabilityInsertAnchor)
			continue
		}

		// Staging file + rename, the same atomic-write pattern
		// ensureExecStartPreHookIn uses for the same reason: systemd
		// reads these on daemon-reload, and a partial write would be a
		// bad state.
		staging := unitPath + ".new"
		if err := os.WriteFile(staging, []byte(newContent), 0644); err != nil {
			fmt.Printf("    WARNING: write staging %s: %v\n", staging, err)
			continue
		}
		if err := os.Rename(staging, unitPath); err != nil {
			fmt.Printf("    WARNING: rename %s → %s: %v\n", staging, unitPath, err)
			_ = os.Remove(staging)
			continue
		}
		modified++
	}
	return modified
}

// unitReferencesGatewayConfig reads a unit file's ExecStart= line for a
// -config path and reports whether that config file declares
// [gateway] enabled = true — the same field gateway_wire.go's
// wireGateway itself keys on to decide whether to bind 80 and 443 at
// all, so this check can never drift from what the runtime actually
// does. A unit with no ExecStart=, no -config flag, or an unreadable
// config file reports false — the conservative default for "leave it
// alone."
func unitReferencesGatewayConfig(unitContent string) bool {
	for _, line := range strings.Split(unitContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ExecStart=") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(trimmed, "ExecStart="))
		for i, f := range fields {
			if f == "-config" && i+1 < len(fields) {
				cfg, err := os.ReadFile(fields[i+1])
				if err != nil {
					return false
				}
				return configDeclaresGatewayEnabled(string(cfg))
			}
		}
		break
	}
	return false
}

// configDeclaresGatewayEnabled reports whether a config file's text sets
// [gateway] enabled = true, scanning only inside the [gateway] table —
// the same lightweight line-scan internal/config/gateway.go's
// sitesFileListsDomain uses for its own one-fact check, rather than a
// full TOML parse.
func configDeclaresGatewayEnabled(configText string) bool {
	inGatewayTable := false
	for _, line := range strings.Split(configText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inGatewayTable = trimmed == "[gateway]"
			continue
		}
		if !inGatewayTable {
			continue
		}
		if strings.HasPrefix(trimmed, "enabled") {
			return strings.Contains(trimmed, "true")
		}
	}
	return false
}

// insertAfterAnchorOnce inserts insert immediately after anchor in text
// and reports true, but only when anchor appears in text exactly
// once — the shape both a fresh render (renderGatewayUnit,
// deploy_gateway.go) and an upgrade patching an older unit
// (ensureGatewayCapabilitiesIn, above) need: insert cleanly when the
// anchor is exactly where expected, and do nothing — rather than guess
// where to go, insert twice, or insert after only one of several
// matches — when it isn't. A caller that cares whether what it's about
// to insert is already present (so running this twice stays harmless)
// checks that itself, first; this helper only ever inserts, and only
// ever once.
func insertAfterAnchorOnce(text, anchor, insert string) (string, bool) {
	if strings.Count(text, anchor) != 1 {
		return text, false
	}
	return strings.Replace(text, anchor, anchor+insert, 1), true
}
