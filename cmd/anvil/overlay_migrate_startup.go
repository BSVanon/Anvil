package main

import (
	"context"
	"fmt"
	"log/slog"

	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const legacyOverlayMigration = "legacy-overlay-v2-to-v3"

// autoMigrateLegacyOverlayKeys upgrades legacy overlay records before the v3
// engine starts. Fresh and already-migrated stores are left untouched.
func autoMigrateLegacyOverlayKeys(db *leveldb.DB, logger *slog.Logger, started ...func(string) error) error {
	legacyCount := countKeysWithPrefix(db, "ovl:")
	if legacyCount == 0 {
		return nil
	}
	v3Count := countKeysWithPrefix(db, "ovl3:")
	if v3Count >= legacyCount {
		return nil
	}
	if len(started) > 0 && started[0] != nil {
		if err := started[0](legacyOverlayMigration); err != nil {
			return fmt.Errorf("record overlay migration start: %w", err)
		}
	}

	if logger != nil {
		logger.Info("v3 detected legacy v2 overlay data — running one-shot migration",
			"legacy_keys", legacyCount,
			"v3_keys_present", v3Count)
	}

	opts := anvilstorage.MigrateOptions{
		LookupBackfiller: makeLookupBackfiller(db, false),
	}
	if logger != nil {
		opts.Logger = func(format string, a ...any) {
			logger.Info("auto-migrate", "line", fmt.Sprintf(format, a...))
		}
	}
	stats, err := anvilstorage.Migrate(context.Background(), db, opts)
	if err != nil {
		return fmt.Errorf("storage.Migrate: %w", err)
	}
	if stats.UnparseableLegacy > 0 || stats.UnparseableKey > 0 {
		return fmt.Errorf("migration found unparseable data: UnparseableLegacy=%d UnparseableKey=%d — run `anvil overlay-migrate -v` to inspect",
			stats.UnparseableLegacy, stats.UnparseableKey)
	}
	if logger != nil {
		logger.Info("v3 auto-migration complete",
			"migrated", stats.Migrated,
			"already_migrated", stats.AlreadyMigrated,
			"lookup_backfilled", stats.LookupBackfilled,
			"lookup_backfill_errors", stats.LookupBackfillErrors)
	}
	return nil
}

func countKeysWithPrefix(db *leveldb.DB, prefix string) int {
	if db == nil {
		return 0
	}
	iter := db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()
	count := 0
	for iter.Next() {
		count++
	}
	return count
}
