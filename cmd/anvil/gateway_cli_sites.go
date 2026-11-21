package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// cmdGatewaySite handles `anvil gateway site add|remove|list`. The sites
// file's own format, validation and concurrency-safe read-modify-write
// live in internal/sitesfile — this file is just the CLI's thin front
// end onto it, the same package a later daemon-side caller will import
// directly rather than shelling out to this binary.
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
		gatewaySiteList(cfg.Gateway.SitesFile, gateway.RegistrationFile(cfg.Node.DataDir))
	case "add":
		assertRoot()
		gatewaySiteAdd(cfg.Gateway.SitesFile, cfg.Gateway.APIHost, posArgs)
	case "remove":
		assertRoot()
		gatewaySiteRemove(cfg.Gateway.SitesFile, gateway.RegistrationFile(cfg.Node.DataDir), posArgs)
	default:
		printGatewayUsage()
		os.Exit(1)
	}
}

type gatewaySiteEntry struct {
	sitesfile.Entry
	registered bool
}

func gatewaySiteEntries(path, registrationPath string) ([]gatewaySiteEntry, error) {
	operator, err := sitesfile.Read(path)
	if err != nil {
		return nil, err
	}
	registered, err := sitesfile.Read(registrationPath)
	if err != nil {
		return nil, err
	}
	entries := make([]gatewaySiteEntry, 0, len(operator)+len(registered))
	for _, entry := range operator {
		entries = append(entries, gatewaySiteEntry{Entry: entry})
	}
	for _, entry := range registered {
		entries = append(entries, gatewaySiteEntry{Entry: entry, registered: true})
	}
	return entries, nil
}

func gatewaySiteList(path, registrationPath string) {
	entries, err := gatewaySiteEntries(path, registrationPath)
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
			if e.registered {
				fmt.Printf("domain %s  (registered; %s)\n", e.Value, liveTXTStatus(ctx, e.Value))
			} else {
				fmt.Printf("domain %s  (%s)\n", e.Value, liveTXTStatus(ctx, e.Value))
			}
		} else {
			fmt.Printf("origin %s\n", e.Value)
		}
	}
}

// gatewaySiteAddEntry is gatewaySiteAdd's error-returning core: parses
// posArgs[0] and adds it to path's sites file, applying apiHost's
// reservation exactly as sitesfile.Add implements it. Split out from
// gatewaySiteAdd's fatal() call so the wiring from a loaded config's
// cfg.Gateway.APIHost through to that refusal is a real, test-asserted
// path (cmd/anvil/gateway_cli_sites_test.go) rather than something only
// a manual CLI run would catch.
func gatewaySiteAddEntry(path, apiHost string, posArgs []string) (sitesfile.Entry, error) {
	if len(posArgs) != 1 {
		return sitesfile.Entry{}, fmt.Errorf("usage: anvil gateway site add <domain|origin>")
	}
	entry, err := sitesfile.ParseEntry(posArgs[0])
	if err != nil {
		return sitesfile.Entry{}, err
	}
	if err := sitesfile.Add(path, entry, apiHost); err != nil {
		return sitesfile.Entry{}, err
	}
	return entry, nil
}

// gatewaySiteAdd adds posArgs[0] to path's sites file. apiHost is this
// node's already-resolved [gateway] api_host (config.Load's own
// resolution rule: the explicit value, otherwise the host of [node]
// public_url) — sitesfile.Add refuses a domain entry that equals it,
// since the API handler always wins that Host match and such an entry
// could never actually be served.
func gatewaySiteAdd(path, apiHost string, posArgs []string) {
	entry, err := gatewaySiteAddEntry(path, apiHost, posArgs)
	if err != nil {
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

func gatewaySiteRemoveEntry(path, registrationPath string, posArgs []string) (sitesfile.Entry, bool, error) {
	if len(posArgs) != 1 {
		return sitesfile.Entry{}, false, fmt.Errorf("usage: anvil gateway site remove <domain|origin>")
	}
	entry, err := sitesfile.ParseEntry(posArgs[0])
	if err != nil {
		return sitesfile.Entry{}, false, err
	}
	operatorRemoved, err := sitesfile.Remove(path, entry)
	if err != nil {
		return sitesfile.Entry{}, false, err
	}
	registeredRemoved, err := sitesfile.Remove(registrationPath, entry)
	if err != nil {
		return sitesfile.Entry{}, false, err
	}
	return entry, operatorRemoved || registeredRemoved, nil
}

func gatewaySiteRemove(path, registrationPath string, posArgs []string) {
	entry, removed, err := gatewaySiteRemoveEntry(path, registrationPath, posArgs)
	if err != nil {
		fatal(err.Error())
	}
	if removed {
		fmt.Printf("removed %s %s\n", entry.Kind, entry.Value)
	} else {
		fmt.Printf("%s %s was not in the sites file\n", entry.Kind, entry.Value)
	}
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
