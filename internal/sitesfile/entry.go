// Package sitesfile implements the gateway's sites file: the operator's
// list of domains and on-chain origins a gateway node serves. It is the
// on-disk contract between whatever reads the list at runtime
// (internal/gateway's allowlist) and whatever edits it (a CLI today, a
// daemon-side caller later) — the same way internal/config's writer and
// reader agree on the TOML format without sharing code.
//
// Every read and write here is safe to call concurrently, from one
// process or several; see lock.go.
package sitesfile

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Entry is one line of the sites file: a "domain <name>" or
// "origin <txid>_<vout>" entry.
type Entry struct {
	Kind  string // "domain" or "origin"
	Value string // normalised: lowercased domain, or lowercased-hex "<txid>_<vout>"
}

var outpointShape = regexp.MustCompile(`^[0-9a-fA-F]{64}_[0-9]+$`)

// LooksLikeOutpoint reports whether raw has the "<64 hex>_<decimal>"
// shape, the signal ParseEntry uses to classify an origin instead of a
// domain.
func LooksLikeOutpoint(raw string) bool { return outpointShape.MatchString(strings.TrimSpace(raw)) }

// ValidateOrigin mirrors internal/gateway's parseOutpoint: a 64-hex txid
// (lowercased) and a decimal vout fitting a uint32.
func ValidateOrigin(raw string) (string, bool) {
	m := outpointShape.FindString(strings.TrimSpace(raw))
	if m == "" {
		return "", false
	}
	parts := strings.SplitN(m, "_", 2)
	vout, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", false
	}
	return strings.ToLower(parts[0]) + "_" + strconv.FormatUint(vout, 10), true
}

var ldhLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDomain mirrors internal/gateway's validateDomain: lowercase,
// strip one trailing dot, require every label to be ASCII LDH, reject IP
// literals. Callers needing api_host's own shape rules (deploy_gateway.go)
// use this same function, so a site domain and the gateway's own host are
// always judged by one rule.
func ValidateDomain(raw string) (string, bool) {
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

// ParseEntry classifies and validates a CLI <domain|origin> argument:
// it's an origin if it has the outpoint shape, a domain otherwise.
func ParseEntry(raw string) (Entry, error) {
	if LooksLikeOutpoint(raw) {
		v, ok := ValidateOrigin(raw)
		if !ok {
			return Entry{}, fmt.Errorf("invalid origin %q: want <64 hex>_<decimal vout>", raw)
		}
		return Entry{Kind: "origin", Value: v}, nil
	}
	v, ok := ValidateDomain(raw)
	if !ok {
		return Entry{}, fmt.Errorf("invalid domain %q", raw)
	}
	return Entry{Kind: "domain", Value: v}, nil
}

// Read parses path's valid "domain "/"origin " lines, skipping comments,
// blanks and malformed lines, in file order. A missing file returns an
// empty slice, not an error — matching internal/gateway.NewAllowlist's
// own "no sites file yet" convention.
//
// Read takes neither lock: a reader racing a writer sees either the old
// file or the new one, never a half-written one, because every write
// here lands via an atomic rename (write.go).
func Read(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []Entry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 && !(len(fields) == 5 && fields[2] == "#" && fields[3] == "registered-by") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "domain":
			if v, ok := ValidateDomain(fields[1]); ok {
				entries = append(entries, Entry{Kind: "domain", Value: v})
			}
		case "origin":
			if v, ok := ValidateOrigin(fields[1]); ok {
				entries = append(entries, Entry{Kind: "origin", Value: v})
			}
		}
	}
	return entries, scanner.Err()
}

// matchesEntry reports whether a sites-file line (already
// whitespace-trimmed) is a "domain"/"origin" line whose normalised value
// equals entry.
func matchesEntry(trimmed string, entry Entry) bool {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	plain := len(fields) == 2
	registered := len(fields) == 5 && fields[2] == "#" && fields[3] == "registered-by"
	if (!plain && !registered) || !strings.EqualFold(fields[0], entry.Kind) {
		return false
	}
	var v string
	var ok bool
	if entry.Kind == "domain" {
		v, ok = ValidateDomain(fields[1])
	} else {
		v, ok = ValidateOrigin(fields[1])
	}
	return ok && v == entry.Value
}
