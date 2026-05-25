package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BSVanon/Anvil/internal/config"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// cmdOverlayMigrate runs the W-4 phase B backfill: reads every legacy
// `ovl:<topic>:<txid>:<vout>` LevelDB entry and writes the canonical v3
// records (ovl3 primary + txi3/topi3/mst3 indexes).
//
// Usage:
//
//	anvil overlay-migrate                    # apply migration
//	anvil overlay-migrate -dry-run           # report counts, write nothing
//	anvil overlay-migrate -config /path/...  # override default anvil.toml
//
// Idempotent. Safe to re-run. Operators upgrading from v2.x.x to v3.0.0
// MUST run this once before serving traffic — without it, the v3 engine
// starts with empty storage even though the existing LevelDB has
// populated legacy ovl: keys.
func cmdOverlayMigrate(args []string) {
	fs := flag.NewFlagSet("overlay-migrate", flag.ExitOnError)
	configPath := fs.String("config", "anvil.toml", "path to config file")
	dryRun := fs.Bool("dry-run", false, "report what would be migrated without writing v3 records")
	verbose := fs.Bool("v", false, "log every migrated record (default: summary only)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "parse flags:", err)
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}

	if !cfg.Overlay.Enabled {
		log.Fatal("overlay.enabled = false in config; nothing to migrate")
	}

	ovDir := filepath.Join(cfg.Node.DataDir, "overlay")
	dir, err := anviloverlay.NewDirectory(ovDir)
	if err != nil {
		log.Fatalf("open overlay directory: %v", err)
	}
	defer dir.Close()

	opts := storage.MigrateOptions{
		DryRun:           *dryRun,
		LookupBackfiller: makeLookupBackfiller(dir.DB(), *dryRun),
	}
	if *verbose {
		opts.Logger = func(format string, a ...any) {
			log.Printf(format, a...)
		}
	}

	mode := "applying"
	if *dryRun {
		mode = "dry-run"
	}
	log.Printf("overlay-migrate: %s against %s", mode, ovDir)

	stats, err := storage.Migrate(context.Background(), dir.DB(), opts)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Summary block — operators may parse stdout for monitoring.
	fmt.Printf("=== overlay-migrate summary ===\n")
	fmt.Printf("  LegacyKeysSeen:    %d\n", stats.LegacyKeysSeen)
	fmt.Printf("  Migrated:          %d\n", stats.Migrated)
	fmt.Printf("  AlreadyMigrated:   %d  (idempotent skips)\n", stats.AlreadyMigrated)
	fmt.Printf("  UnparseableLegacy: %d  (corrupt JSON values)\n", stats.UnparseableLegacy)
	fmt.Printf("  UnparseableKey:    %d  (key didn't fit ovl:<topic>:<txid>:<vout>)\n", stats.UnparseableKey)
	if *dryRun {
		fmt.Println("  (dry-run: no v3 records were written)")
	}

	fmt.Printf("  LookupBackfilled:  %d  (canonical lk_* index entries written)\n", stats.LookupBackfilled)
	fmt.Printf("  LookupBackfillErr: %d  (lookup-side errors; non-fatal)\n", stats.LookupBackfillErrors)
	fmt.Println()
	fmt.Println("Known limitation: migrated records have no BEEF in storage (legacy")
	fmt.Println("engine never stored BEEF after parsing). Canonical /lookup hydrates")
	fmt.Println("each result via Storage.FindOutput(...includeBEEF=true) and drops")
	fmt.Println("entries where output.Beef is nil — so migrated records are present")
	fmt.Println("in ovl3 + lk_* indexes but NOT surfaced via /lookup or /overlay/query")
	fmt.Println("until BEEF arrives (re-submit, JungleBus sync, or a future fetch")
	fmt.Println("command). The migration preserves them for re-admission safety +")
	fmt.Println("for when BEEF eventually shows up.")

	// Non-zero exit if any data was unparseable so monitoring catches
	// silent data-quality regressions.
	if stats.UnparseableLegacy > 0 || stats.UnparseableKey > 0 {
		os.Exit(1)
	}
}

// makeLookupBackfiller returns the storage.MigrateOptions.LookupBackfiller
// callback that dispatches each migrated record to the appropriate
// canonical lookup service. The four canonical lookup services are
// constructed against the SAME LevelDB the storage adapter uses — they
// share the underlying database via different key-family prefixes
// (lk_uhrp:, lk_dexswap:, lk_ordlock:, lk_ordlockbuy:).
//
// dryRun=true short-circuits the callback so a sizing pass doesn't
// write lookup-side state either.
func makeLookupBackfiller(db *leveldb.DB, dryRun bool) func(string, *transaction.Outpoint, json.RawMessage) error {
	if dryRun {
		return func(string, *transaction.Outpoint, json.RawMessage) error { return nil }
	}
	uhrp := lookups.NewUHRPLookupService(db)
	dex := lookups.NewDEXSwapLookupService(db)
	ordlock := lookups.NewOrdLockLookupService(db)
	ordlockBuy := lookups.NewOrdLockBuyLookupService(db)
	return func(topic string, op *transaction.Outpoint, metadata json.RawMessage) error {
		switch topic {
		case topics.UHRPTopicName:
			return uhrp.BackfillFromLegacyMetadata(op, metadata)
		case topics.DEXSwapTopicName:
			return dex.BackfillFromLegacyMetadata(op, metadata)
		case topics.OrdLockTopicName:
			return ordlock.BackfillFromLegacyMetadata(op, metadata)
		case topics.OrdLockBuyTopicName:
			return ordlockBuy.BackfillFromLegacyMetadata(op, metadata)
		default:
			// Unknown topic in legacy data → no canonical lookup to
			// backfill. Storage record was still written; operator
			// can decide whether to clean up via a future tool.
			return nil
		}
	}
}
