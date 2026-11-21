package sitesfile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
// before adding any sites. A fresh file is created root:anvil (best
// effort); a file that already exists keeps its current owner — see
// AtomicWriteFile.
//
// Safe to call concurrently, from this process or another: the whole
// read-modify-write is serialised by WithLock (lock.go).
func Add(path string, entry Entry, reservedHost string) error {
	return WithLock(path, func() error {
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
		uid, gid := newSiteFileOwner()
		return AtomicWriteFile(path, []byte(text), 0640, uid, gid)
	})
}

// Remove drops every line matching entry from path's sites file,
// preserving everything else (including comments) verbatim. Reports
// whether anything was actually removed.
//
// Safe to call concurrently, the same as Add.
func Remove(path string, entry Entry) (bool, error) {
	var removed bool
	err := WithLock(path, func() error {
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
		uid, gid := newSiteFileOwner()
		return AtomicWriteFile(path, []byte(text), 0640, uid, gid)
	})
	return removed, err
}

// newSiteFileOwner is the owner AtomicWriteFile applies to a sites file
// (or, via WithLock's own lock file — see lock.go — the lock file
// itself) when it doesn't already exist: uid left alone (-1 — every
// caller here already runs as root behind assertRoot(), so the fresh
// file os.CreateTemp made is already root-owned) and gid set to the
// "anvil" group, looked up by name so this works whatever numeric gid
// the install gave that group. Stricter than a config file's usual
// world-readable mode, since a sites list can reveal which private
// domains or origins this node knows about.
//
// Best effort: a machine with no "anvil" group at all — a developer's
// workstation running this package's own tests, say — gets -1 for both,
// so AtomicWriteFile leaves the file exactly as os.CreateTemp made it,
// the same as if ownership were never tracked at all.
func newSiteFileOwner() (uid, gid int) {
	uid, gid = -1, -1
	g, err := user.LookupGroup("anvil")
	if err != nil {
		return uid, gid
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return uid, gid
	}
	return uid, n
}

// AtomicWriteFile durably replaces path's contents: stage to a unique
// temp file in path's own directory (os.CreateTemp, so the later rename
// stays on one filesystem and is atomic), set its owner and perm, fsync
// the temp file, rename it over path, then fsync the containing
// directory so the rename itself — not only the bytes — survives a
// crash. The owner is always set before the rename, never after: there
// is no window where path exists with the wrong owner for something
// else to observe.
//
// Ownership: if path already exists, its current owner and group are
// copied onto the replacement — replacing a hardened file (say,
// root:anvil) must never silently hand it back some other owner. If
// path does not exist yet, newUID and newGID are applied instead
// (either may be -1, meaning "leave it at whatever os.CreateTemp already
// gave it" — the calling process's own ids). Every chown here is best
// effort: a non-root caller's chown normally fails with EPERM, and the
// write and rename still succeed, leaving the temp file's default owner —
// exactly as if this package never tried.
//
// Exported so other callers that need the same durability (the gateway
// peers writer, for its anvil.toml rewrite) can reuse one proven
// implementation instead of a second, possibly-divergent one.
func AtomicWriteFile(path string, data []byte, perm os.FileMode, newUID, newGID int) error {
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

	uid, gid := newUID, newGID
	if existing, statErr := os.Stat(path); statErr == nil {
		if u, g, ok := statOwner(existing); ok {
			uid, gid = u, g
		}
	}
	if uid >= 0 || gid >= 0 {
		_ = tmp.Chown(uid, gid) // best effort — see the doc comment above
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
