package gateway

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Snapshot is one parsed, immutable version of the sites file: the set of
// allowed domains and the set of allowed origins (decision 3's two entry
// kinds). The zero value is empty — nothing allowed.
type Snapshot struct {
	domains map[string]struct{}
	origins map[string]struct{}
}

// HasDomain reports whether host (already Host-header-normalised by the
// caller — see hostOnly) has an explicit "domain" entry.
func (s *Snapshot) HasDomain(host string) bool {
	if s == nil {
		return false
	}
	_, ok := s.domains[strings.ToLower(host)]
	return ok
}

// HasOrigin reports whether origin (a normalised txid_vout) has an
// explicit "origin" entry.
func (s *Snapshot) HasOrigin(origin string) bool {
	if s == nil {
		return false
	}
	_, ok := s.origins[origin]
	return ok
}

// HasAnyOrigin reports whether the sites file lists any "origin" entries
// at all. Policy uses this to decide whether a Host with no domain entry
// is even worth a speculative TXT lookup (decision 4's flood guard).
func (s *Snapshot) HasAnyOrigin() bool {
	return s != nil && len(s.origins) > 0
}

// Allowlist is the sites file's live, hot-reloaded state (decision 7). The
// zero value is not usable; construct with NewAllowlist.
type Allowlist struct {
	path    string
	apiHost string // normalised; a "domain" entry equal to this is ignored on reload (D2)
	logger  *slog.Logger

	current atomic.Pointer[Snapshot]

	// mtime/loggedBadAt/loggedOverlapAt are only touched from Reload.
	// cmd/anvil's wiring calls Reload from a single ticker goroutine, so
	// no lock is needed; tests call it directly and synchronously for the
	// same reason.
	mtime           time.Time
	loggedBadAt     time.Time
	loggedOverlapAt time.Time
}

// NewAllowlist loads path once and returns an Allowlist reflecting it. A
// missing file is not an error — an operator can turn gateway mode on
// before adding any sites and add them later with the CLI (B7b) — it just
// means nothing is allowed yet. Call Reload periodically (cmd/anvil's
// wiring runs it off a 5s ticker, per decision 7) to pick up edits with no
// restart.
//
// apiHost (internal/config's resolved [gateway] api_host) is never allowed
// as a site: D2's "the API always wins over a site entry" is already
// structurally guaranteed by Router (it checks api_host before ever
// consulting Sites), but a "domain" entry equal to apiHost is additionally
// stripped from every snapshot outright, on load and on every reload, with
// one warning per bad mtime — so an operator sees the misconfiguration
// instead of a silently-ineffective sites-file line. internal/config's
// Load separately refuses this same overlap outright at config load time;
// this is the hot-reload-time half of D2's overlap rule, for an entry
// added after the node is already running.
func NewAllowlist(path, apiHost string, logger *slog.Logger) *Allowlist {
	if logger == nil {
		logger = slog.Default()
	}
	a := &Allowlist{path: path, apiHost: normalizeHost(apiHost), logger: logger}
	a.current.Store(&Snapshot{})
	a.Reload()
	return a
}

// Snapshot returns the current parsed sites file. Always non-nil.
func (a *Allowlist) Snapshot() *Snapshot {
	if a == nil {
		return &Snapshot{}
	}
	if s := a.current.Load(); s != nil {
		return s
	}
	return &Snapshot{}
}

// Reload re-reads the sites file if its mtime changed since the last
// successful check, parses it, and atomically swaps in the new snapshot.
// A parse error — or the file vanishing after one existed — keeps the
// last good snapshot and logs once per distinct mtime, so a broken edit
// doesn't spam the log every 5s until it's fixed (decision 7). Not safe
// for concurrent callers; cmd/anvil's wiring runs it from one goroutine.
func (a *Allowlist) Reload() {
	info, err := os.Stat(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			// No sites file yet is not a parse error — nothing to serve
			// until one is added or the configured path is fixed.
			return
		}
		a.logBad(a.mtime, fmt.Errorf("stat sites file: %w", err))
		return
	}
	if !a.mtime.IsZero() && !info.ModTime().After(a.mtime) {
		return
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		a.logBad(info.ModTime(), fmt.Errorf("read sites file: %w", err))
		return
	}
	snap, err := parseSitesFile(data)
	if err != nil {
		a.logBad(info.ModTime(), err)
		return
	}
	if a.apiHost != "" {
		if _, ok := snap.domains[a.apiHost]; ok {
			delete(snap.domains, a.apiHost)
			a.logOverlap(info.ModTime())
		}
	}
	a.mtime = info.ModTime()
	a.current.Store(snap)
}

func (a *Allowlist) logBad(mtime time.Time, err error) {
	if mtime.Equal(a.loggedBadAt) {
		return
	}
	a.loggedBadAt = mtime
	a.logger.Warn("gateway sites file invalid, keeping last good snapshot", "path", a.path, "error", err)
}

// logOverlap warns, once per distinct mtime, that the sites file lists
// api_host as a "domain" entry — D2's overlap rule — and that the entry
// was ignored rather than silently shadowed by Router's api_host-first
// ordering.
func (a *Allowlist) logOverlap(mtime time.Time) {
	if mtime.Equal(a.loggedOverlapAt) {
		return
	}
	a.loggedOverlapAt = mtime
	a.logger.Warn("gateway sites file lists api_host as a domain entry, ignoring it", "path", a.path, "api_host", a.apiHost)
}

// parseSitesFile parses the whole file at once, all-or-nothing: either
// every line is valid (a comment, blank, "domain <name>" or
// "origin <txid>_<vout>") and the result is a complete new Snapshot, or
// the first bad line fails the whole parse and the caller keeps its
// previous Snapshot — decision 7's atomic swap means a half-good edit
// never silently drops the other, still-valid entries.
func parseSitesFile(data []byte) (*Snapshot, error) {
	snap := &Snapshot{domains: map[string]struct{}{}, origins: map[string]struct{}{}}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf(`line %d: expected "domain <name>" or "origin <txid>_<vout>", got %q`, lineNo, line)
		}
		switch strings.ToLower(fields[0]) {
		case "domain":
			d, ok := validateDomain(fields[1])
			if !ok {
				return nil, fmt.Errorf("line %d: invalid domain %q", lineNo, fields[1])
			}
			snap.domains[d] = struct{}{}
		case "origin":
			o, ok := parseOutpoint(fields[1])
			if !ok {
				return nil, fmt.Errorf("line %d: invalid origin %q", lineNo, fields[1])
			}
			snap.origins[o] = struct{}{}
		default:
			return nil, fmt.Errorf("line %d: unknown entry kind %q", lineNo, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan sites file: %w", err)
	}
	return snap, nil
}

// ldhLabel matches one ASCII LDH (letters, digits, hyphen) label: 1-63
// chars, no leading/trailing hyphen.
var ldhLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateDomain lowercases raw, strips one trailing dot, and requires
// every label to be ASCII LDH (decision 7) and the whole string to not be
// an IP literal (N2): a bare IPv4 or IPv6 address is never a meaningful
// "domain" entry for the _ordfs TXT convention this package implements,
// and refusing it outright is clearer than relying on IPv6's colons to
// incidentally fail the LDH check. Punycode (xn--...) is already plain
// ASCII LDH and passes; raw Unicode does not.
func validateDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	if net.ParseIP(d) != nil {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if !ldhLabel.MatchString(label) {
			return "", false
		}
	}
	return d, true
}

// outpointRe matches a "<64 hex>_<decimal>" outpoint, case-insensitive on
// the hex part — shared by the sites file's "origin" entries and txt.go's
// ordfs= TXT values, so there is exactly one notion of a valid outpoint
// string in this package.
var outpointRe = regexp.MustCompile(`^([0-9a-fA-F]{64})_([0-9]+)$`)

// parseOutpoint validates and normalises a txid_vout string: the txid is
// lowercased, and the vout must be decimal and fit in a uint32 — at most
// 2^32-1 (decision 4).
func parseOutpoint(raw string) (string, bool) {
	m := outpointRe.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	vout, err := strconv.ParseUint(m[2], 10, 32)
	if err != nil {
		return "", false
	}
	return strings.ToLower(m[1]) + "_" + strconv.FormatUint(vout, 10), true
}
