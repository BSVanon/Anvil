package sitesfile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrReservedHost is wrapped into the error Add returns when a domain
// entry equals the gateway's reserved host. The API handler always wins
// that Host match, so a site entry there could never actually be served.
var ErrReservedHost = errors.New("refused: equals this gateway's own api_host, which is never reachable as a site")

// Add appends entry to path's sites file if not already present
// (idempotent) and, for a domain entry, not equal to reservedHost
// (compared the same way ValidateDomain normalises: lowercased, one
// trailing dot ignored). reservedHost may be empty, meaning nothing is
// reserved. Every existing line is preserved verbatim, including
// comments.
//
// A missing file is created fresh — an operator may turn gateway mode on
// before adding any sites.
//
// Safe to call concurrently, from this process or another: the whole
// read-modify-write is serialised by withLock (lock.go).
func Add(path string, entry Entry, reservedHost string) error {
	return withLock(path, func() error {
		if entry.Kind == "domain" && reservedHost != "" {
			if normHost, ok := ValidateDomain(reservedHost); ok && normHost == entry.Value {
				return fmt.Errorf("%q: %w", entry.Value, ErrReservedHost)
			}
		}
		existing, err := Read(path)
		if err != nil {
			return fmt.Errorf("read sites file: %w", err)
		}
		for _, e := range existing {
			if e.Kind == entry.Kind && e.Value == entry.Value {
				return fmt.Errorf("%s %s is already in the sites file", entry.Kind, entry.Value)
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read sites file: %w", err)
		}
		text := string(raw)
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += fmt.Sprintf("%s %s\n", entry.Kind, entry.Value)
		if err := AtomicWriteFile(path, []byte(text), 0640); err != nil {
			return err
		}
		chownAnvilGroup(path)
		return nil
	})
}

// Remove drops every line matching entry from path's sites file,
// preserving everything else (including comments) verbatim. Reports
// whether anything was actually removed.
//
// Safe to call concurrently, the same as Add.
func Remove(path string, entry Entry) (bool, error) {
	var removed bool
	err := withLock(path, func() error {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("read sites file: %w", err)
		}
		var kept []string
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if matchesEntry(trimmed, entry) {
				removed = true
				continue
			}
			kept = append(kept, line)
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if !removed {
			return nil
		}
		text := strings.Join(kept, "\n")
		if len(kept) > 0 {
			text += "\n"
		}
		if err := AtomicWriteFile(path, []byte(text), 0640); err != nil {
			return err
		}
		chownAnvilGroup(path)
		return nil
	})
	return removed, err
}

// chownAnvilGroup chowns path root:anvil — stricter than a config file's
// usual world-readable mode, since a sites list can reveal which private
// domains or origins this node knows about. Best-effort: a system with no
// "anvil" group (e.g. a dev machine running the test suite) leaves the
// file owned by whoever is running it, which is fine off-target.
func chownAnvilGroup(path string) {
	_ = exec.Command("chown", "root:anvil", path).Run()
}

// AtomicWriteFile durably replaces path's contents: stage to a unique
// temp file in path's own directory (os.CreateTemp, so the later rename
// stays on one filesystem and is atomic), apply perm, fsync the temp
// file, rename it over path, then fsync the containing directory so the
// rename itself — not only the bytes — survives a crash.
//
// Exported so other callers that need the same durability (the gateway
// peers writer, for its anvil.toml rewrite) can reuse one proven
// implementation instead of a second, possibly-divergent one.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create staging file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod staging file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close staging file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename staging file: %w", err)
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for fsync: %w", err)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}
