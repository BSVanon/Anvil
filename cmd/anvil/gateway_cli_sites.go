package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/gateway"
)

// siteEntry is one line of the gateway sites file: a "domain <name>" or
// "origin <txid>_<vout>" entry, in the exact format
// internal/gateway.Allowlist parses at runtime. This file implements its
// own independent reader/writer for that same on-disk text format rather
// than reaching into internal/gateway's unexported parser, so the
// mechanism and this CLI agree on the file format, not on a shared Go
// API — the same way internal/config's writer (deploy) and reader (Load)
// agree on the TOML format without sharing code.
type siteEntry struct {
	Kind  string // "domain" or "origin"
	Value string // normalised: lowercased domain, or lowercased-hex "<txid>_<vout>"
}

// cmdGatewaySite handles `anvil gateway site add|remove|list`.
func cmdGatewaySite(args []string) {
	if len(args) == 0 {
		printGatewayUsage()
		os.Exit(1)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("gateway site "+sub, flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	_ = fs.Parse(rest)
	posArgs := fs.Args()

	cfg := loadGatewayConfigOrFatal(*configPath)

	switch sub {
	case "list":
		gatewaySiteList(cfg.Gateway.SitesFile)
	case "add":
		assertRoot()
		gatewaySiteAdd(cfg.Gateway.SitesFile, posArgs)
	case "remove":
		assertRoot()
		gatewaySiteRemove(cfg.Gateway.SitesFile, posArgs)
	default:
		printGatewayUsage()
		os.Exit(1)
	}
}

func gatewaySiteList(path string) {
	entries, err := readSiteEntries(path)
	if err != nil {
		fatal("sites file: " + err.Error())
	}
	if len(entries) == 0 {
		fmt.Println("no sites configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, e := range entries {
		if e.Kind == "domain" {
			fmt.Printf("domain %s  (%s)\n", e.Value, liveTXTStatus(ctx, e.Value))
		} else {
			fmt.Printf("origin %s\n", e.Value)
		}
	}
}

func gatewaySiteAdd(path string, posArgs []string) {
	if len(posArgs) != 1 {
		fatal("usage: anvil gateway site add <domain|origin>")
	}
	entry, err := parseSiteArg(posArgs[0])
	if err != nil {
		fatal(err.Error())
	}
	if err := addSiteEntry(path, entry); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("added %s %s\n", entry.Kind, entry.Value)
	if entry.Kind == "domain" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		fmt.Println(liveTXTStatus(ctx, entry.Value))
	}
	fmt.Println("no restart needed — the gateway hot-reloads the sites file")
}

func gatewaySiteRemove(path string, posArgs []string) {
	if len(posArgs) != 1 {
		fatal("usage: anvil gateway site remove <domain|origin>")
	}
	entry, err := parseSiteArg(posArgs[0])
	if err != nil {
		fatal(err.Error())
	}
	removed, err := removeSiteEntry(path, entry)
	if err != nil {
		fatal(err.Error())
	}
	if removed {
		fmt.Printf("removed %s %s\n", entry.Kind, entry.Value)
	} else {
		fmt.Printf("%s %s was not in the sites file\n", entry.Kind, entry.Value)
	}
}

// parseSiteArg classifies and validates a CLI <domain|origin> argument:
// it's an origin if it has the outpoint shape, a domain otherwise.
func parseSiteArg(raw string) (siteEntry, error) {
	if looksLikeOutpoint(raw) {
		v, ok := validateSiteOrigin(raw)
		if !ok {
			return siteEntry{}, fmt.Errorf("invalid origin %q: want <64 hex>_<decimal vout>", raw)
		}
		return siteEntry{Kind: "origin", Value: v}, nil
	}
	v, ok := validateSiteDomain(raw)
	if !ok {
		return siteEntry{}, fmt.Errorf("invalid domain %q", raw)
	}
	return siteEntry{Kind: "domain", Value: v}, nil
}

var outpointShape = regexp.MustCompile(`^[0-9a-fA-F]{64}_[0-9]+$`)

func looksLikeOutpoint(raw string) bool { return outpointShape.MatchString(strings.TrimSpace(raw)) }

// validateSiteOrigin mirrors internal/gateway's parseOutpoint: a 64-hex
// txid (lowercased) and a decimal vout fitting a uint32.
func validateSiteOrigin(raw string) (string, bool) {
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

var siteLDHLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateSiteDomain mirrors internal/gateway's validateDomain: lowercase,
// strip one trailing dot, require every label to be ASCII LDH, reject IP
// literals.
func validateSiteDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	if net.ParseIP(d) != nil {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if !siteLDHLabel.MatchString(label) {
			return "", false
		}
	}
	return d, true
}

// readSiteEntries parses path's valid "domain "/"origin " lines, skipping
// comments, blanks and malformed lines, in file order. A missing file
// returns an empty slice, not an error — matching
// internal/gateway.NewAllowlist's own "no sites file yet" convention.
func readSiteEntries(path string) ([]siteEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []siteEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "domain":
			if v, ok := validateSiteDomain(fields[1]); ok {
				entries = append(entries, siteEntry{Kind: "domain", Value: v})
			}
		case "origin":
			if v, ok := validateSiteOrigin(fields[1]); ok {
				entries = append(entries, siteEntry{Kind: "origin", Value: v})
			}
		}
	}
	return entries, scanner.Err()
}

// addSiteEntry appends entry to path's sites file if not already present
// (idempotent), preserving every existing line verbatim including
// comments, and writes atomically with root:anvil 0640. A missing file
// is created fresh — an operator may turn gateway mode on before adding
// any sites.
func addSiteEntry(path string, entry siteEntry) error {
	existing, err := readSiteEntries(path)
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
	return writeSitesFileAtomic(path, text)
}

// removeSiteEntry drops every line matching entry from path's sites
// file, preserving everything else (including comments) verbatim.
// Reports whether anything was actually removed.
func removeSiteEntry(path string, entry siteEntry) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read sites file: %w", err)
	}
	var kept []string
	removed := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if matchesSiteEntry(trimmed, entry) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	text := strings.Join(kept, "\n")
	if len(kept) > 0 {
		text += "\n"
	}
	return true, writeSitesFileAtomic(path, text)
}

// matchesSiteEntry reports whether a sites-file line (already
// whitespace-trimmed) is a "domain"/"origin" line whose normalised value
// equals entry.
func matchesSiteEntry(trimmed string, entry siteEntry) bool {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	if len(fields) != 2 || !strings.EqualFold(fields[0], entry.Kind) {
		return false
	}
	var v string
	var ok bool
	if entry.Kind == "domain" {
		v, ok = validateSiteDomain(fields[1])
	} else {
		v, ok = validateSiteOrigin(fields[1])
	}
	return ok && v == entry.Value
}

// writeSitesFileAtomic writes data to path via a temp file plus rename,
// then chowns it root:anvil with mode 0640 — stricter than a config
// file's usual 0644, since a sites list can reveal which private
// domains or origins this node knows about.
func writeSitesFileAtomic(path, data string) error {
	staging := path + ".new"
	if err := os.WriteFile(staging, []byte(data), 0640); err != nil {
		return fmt.Errorf("write staging sites file: %w", err)
	}
	if err := os.Rename(staging, path); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("rename staging sites file: %w", err)
	}
	_ = exec.Command("chown", "root:anvil", path).Run()
	return nil
}

// liveTXTStatus resolves domain's _ordfs TXT record right now — a fresh
// Resolver, not internal/gateway's own request-serving cache, since this
// is a one-shot operator diagnostic, not traffic — and returns a one-line
// human description.
func liveTXTStatus(ctx context.Context, domain string) string {
	resolver := gateway.NewResolver(gateway.ResolverConfig{})
	origin, ok := resolver.Lookup(ctx, domain, false)
	if !ok {
		return "no _ordfs TXT record found"
	}
	return "ordfs=" + origin
}
