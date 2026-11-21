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

	"github.com/BurntSushi/toml"
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
		hasAmbient := strings.Contains(content, gatewayCapabilityAmbient)
		hasBoundingSet := strings.Contains(content, gatewayCapabilityBoundingSet)
		if hasAmbient && hasBoundingSet {
			continue // already present
		}
		if !unitReferencesGatewayConfig(content) {
			continue // the gateway is off for this node: nothing to add
		}
		newContent, ok := insertAfterAnchorOnce(content, gatewayCapabilityInsertAnchor, missingGatewayCapabilityLines(hasAmbient, hasBoundingSet))
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

// missingGatewayCapabilityLines returns the text to insert immediately
// after gatewayCapabilityInsertAnchor for a unit missing one or both
// capability lines: the full block (with its explanatory comment) when
// neither line is present yet, or just the one line that's missing — no
// comment, and never a second copy of the line already there — when
// only one is. Only ever called when at least one is missing:
// ensureGatewayCapabilitiesIn's own hasAmbient && hasBoundingSet check
// skips the unit entirely before reaching here when both are present.
func missingGatewayCapabilityLines(hasAmbient, hasBoundingSet bool) string {
	switch {
	case !hasAmbient && !hasBoundingSet:
		return gatewayCapabilityInsertBlock
	case !hasAmbient:
		return "\n" + gatewayCapabilityAmbient
	default: // !hasBoundingSet
		return "\n" + gatewayCapabilityBoundingSet
	}
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
// [gateway] enabled = true, by decoding just that one field with the
// same TOML library internal/config uses to load the real config
// (github.com/BurntSushi/toml, already a direct dependency) rather than
// a line scan. A real parse is needed here, not a lightweight
// prefix/substring check: a line scan can't tell "enabled" from
// "enabled_metrics" (a prefix match), and can't tell a value from a
// trailing comment that happens to contain the word "true" (a substring
// match) — both false positives this function used to produce. A config
// that fails to parse as TOML at all reports false, the same
// conservative "leave it alone" default unitReferencesGatewayConfig
// already uses for an unreadable file.
func configDeclaresGatewayEnabled(configText string) bool {
	var cfg struct {
		Gateway struct {
			Enabled bool `toml:"enabled"`
		} `toml:"gateway"`
	}
	if err := toml.Unmarshal([]byte(configText), &cfg); err != nil {
		return false
	}
	return cfg.Gateway.Enabled
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
