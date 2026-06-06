package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BSVanon/Anvil/internal/config"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
)

// cmdPruneAds removes this node's redundant duplicate SHIP/SLAP
// advertisement records, keeping the most-recent record per topic/service.
// It exists to clean up duplicate self-advertisements accumulated by a
// re-mint loop (the v3.1.x SHIP/SLAP flood); it never touches other
// operators' ads (filtered to node.public_url).
//
// MUST be run with the anvil daemon STOPPED — the overlay LevelDB is
// single-process. Dry-run by default.
//
//	anvil prune-ads -config /etc/anvil/node-a.toml          # report only
//	anvil prune-ads -config /etc/anvil/node-a.toml -apply   # delete
func cmdPruneAds(args []string) {
	fs := flag.NewFlagSet("prune-ads", flag.ExitOnError)
	configPath := fs.String("config", "anvil.toml", "path to config file")
	apply := fs.Bool("apply", false, "actually delete duplicates (default: dry-run report only)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "parse flags:", err)
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	domain := cfg.Node.PublicURL
	if domain == "" {
		log.Fatal("node.public_url is empty in config; nothing of ours to prune")
	}

	ovDir := filepath.Join(cfg.Node.DataDir, "overlay")
	dir, err := anviloverlay.NewDirectory(ovDir)
	if err != nil {
		log.Fatalf("open overlay directory (is the anvil daemon stopped?): %v", err)
	}
	defer dir.Close()

	ctx := context.Background()
	shipPlan, err := federation.NewSHIPStorage(dir.DB()).PruneDuplicatesByDomain(ctx, domain, *apply)
	if err != nil {
		log.Fatalf("prune SHIP: %v", err)
	}
	slapPlan, err := federation.NewSLAPStorage(dir.DB()).PruneDuplicatesByDomain(ctx, domain, *apply)
	if err != nil {
		log.Fatalf("prune SLAP: %v", err)
	}

	mode, verb := "DRY RUN — no changes (re-run with -apply to delete)", "would delete"
	if *apply {
		mode, verb = "APPLIED", "deleted"
	}
	fmt.Println("=== Anvil prune-ads ===")
	fmt.Printf("  mode:   %s\n", mode)
	fmt.Printf("  domain: %s\n", domain)
	fmt.Printf("  SHIP:   kept %d topic(s), %s %d duplicate record(s)\n", shipPlan.Kept, verb, shipPlan.Deleted)
	fmt.Printf("  SLAP:   kept %d service(s), %s %d duplicate record(s)\n", slapPlan.Kept, verb, slapPlan.Deleted)
	if *apply {
		fmt.Println("  Done. Restart the daemon (e.g. sudo systemctl start anvil-a).")
	}
}
