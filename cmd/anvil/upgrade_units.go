package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ensureExecStartPreHook inspects every anvil-*.service unit file in the
// standard systemd location and, if the unit ExecStarts the anvil binary
// but has no ExecStartPre=...doctor --locks-only line, inserts one
// immediately before the ExecStart line. Returns the number of files
// modified.
//
// Units written by older versions with the legacy `--fix-locks-only`
// alias are silently rewritten to the canonical `--locks-only` form so
// the unit file matches what a fresh deploy would produce.
//
// Idempotent: if the canonical hook is already present, the file is
// untouched. The modification is conservative (inserts or rewrites a
// single line) so operator customizations above or below that section
// are preserved.
//
// Failures on individual files are logged but don't abort the upgrade —
// the binary replacement and service restart are the primary goals;
// unit-file augmentation is a belt-on-top-of-suspenders safety feature.
func ensureExecStartPreHook() int {
	return ensureExecStartPreHookIn("/etc/systemd/system")
}

// ensureExecStartPreHookIn is the testable core of ensureExecStartPreHook.
// Tests pass a tempdir; production calls use /etc/systemd/system.
func ensureExecStartPreHookIn(systemdDir string) int {
	const hookLine = "ExecStartPre=/opt/anvil/anvil doctor --locks-only"
	const legacyHookLine = "ExecStartPre=/opt/anvil/anvil doctor --fix-locks-only"

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
		// Only touch files that actually invoke our binary; don't stomp
		// on any unrelated unit someone happened to name anvil-*.service.
		if !strings.Contains(content, "/opt/anvil/anvil") {
			continue
		}
		if strings.Contains(content, hookLine) {
			continue // already hooked with canonical flag
		}

		lines := strings.Split(content, "\n")
		var out []string
		inserted := false
		// If a legacy --fix-locks-only hook is present, rewrite in place
		// to the canonical form. Otherwise insert a fresh hook line
		// immediately before the first ExecStart= line.
		if strings.Contains(content, legacyHookLine) {
			for _, line := range lines {
				if strings.TrimSpace(line) == legacyHookLine {
					out = append(out, hookLine)
					inserted = true
					continue
				}
				out = append(out, line)
			}
		} else {
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if !inserted && strings.HasPrefix(trimmed, "ExecStart=") {
					out = append(out, hookLine)
					inserted = true
				}
				out = append(out, line)
			}
		}
		if !inserted {
			continue // no ExecStart= line found; unfamiliar shape, skip
		}

		newContent := strings.Join(out, "\n")
		// Write via a staging file + rename for atomicity (same pattern
		// as the binary install): systemd reads these on daemon-reload
		// and a partial write would be a bad state.
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

// needsV3Migrate returns true when the upgrade is crossing the v2 → v3
// boundary (current major < 3 AND new major >= 3). v3.0.0 is the first
// release where the canonical engine uses the `ovl3:` LevelDB key family;
// without a one-pass `anvil overlay-migrate` against each node's data,
// the v3 daemon boots clean but serves no admitted records until BEEF
// arrives. Fresh installs (current="") have nothing to migrate from and
// return false.
func needsV3Migrate(currentVer, newVer string) bool {
	if strings.TrimSpace(currentVer) == "" {
		return false
	}
	cur := parseVersion(currentVer)
	nxt := parseVersion(newVer)
	if cur == [3]int{0, 0, 0} {
		return false
	}
	return cur[0] < 3 && nxt[0] >= 3
}

// extractServiceConfigs returns the `-config <path>` argument from each
// service's unit-file ExecStart= line. Used by the upgrade migration hook
// so we run `overlay-migrate` against the exact config systemd uses for
// each node — never glob /etc/anvil/*.toml, which can drift from reality
// when operators have custom paths or non-default config names.
//
// systemdDir is the directory containing the unit files (production:
// /etc/systemd/system). services is the list of service basenames
// without the .service suffix.
//
// Units without an ExecStart= line, without /opt/anvil/anvil in the
// ExecStart= command, or without a -config flag are silently skipped.
func extractServiceConfigs(systemdDir string, services []string) map[string]string {
	result := map[string]string{}
	for _, svc := range services {
		unitPath := filepath.Join(systemdDir, svc+".service")
		raw, err := os.ReadFile(unitPath)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "ExecStart=") {
				continue
			}
			cmd := strings.TrimPrefix(trimmed, "ExecStart=")
			if !strings.Contains(cmd, "/opt/anvil/anvil") {
				continue
			}
			fields := strings.Fields(cmd)
			for i, f := range fields {
				if f == "-config" && i+1 < len(fields) {
					result[svc] = fields[i+1]
					break
				}
			}
			break
		}
	}
	return result
}

// serviceRunAsUser inspects each service's unit file for User= and returns
// the first non-root value found. Falls back to "anvil" — the canonical
// runtime user that `anvil deploy` creates and that every production unit
// uses. Used by the upgrade-time overlay-migrate hook to keep new LevelDB
// files owned by the same user the daemon runs as.
func serviceRunAsUser(systemdDir string, services []string) string {
	for _, svc := range services {
		raw, err := os.ReadFile(filepath.Join(systemdDir, svc+".service"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "User=") {
				continue
			}
			user := strings.TrimSpace(strings.TrimPrefix(trimmed, "User="))
			if user != "" && user != "root" {
				return user
			}
		}
	}
	return "anvil"
}

// copyFileE copies src to dst with given permissions, returning any error.
// Unlike copyFile (deploy.go), this does not call fatal — the caller decides.
func copyFileE(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return out.Close()
}
