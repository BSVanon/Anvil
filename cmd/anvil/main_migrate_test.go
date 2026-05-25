package main

import (
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

// TestAutoMigrateLegacyOverlayKeys_NoLegacyData verifies a fresh
// install (no `ovl:` keys at all) is a clean no-op. This is the
// most-common path on a freshly-deployed v3 node.
func TestAutoMigrateLegacyOverlayKeys_NoLegacyData(t *testing.T) {
	dir := t.TempDir()
	db, err := leveldb.OpenFile(filepath.Join(dir, "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := autoMigrateLegacyOverlayKeys(db, nil); err != nil {
		t.Fatalf("expected nil error on fresh install, got: %v", err)
	}
}

// TestAutoMigrateLegacyOverlayKeys_AlreadyMigrated verifies a node
// where both legacy `ovl:` and v3 `ovl3:` keys exist with v3Count >=
// legacyCount is a clean no-op (the migration has already happened).
// This is the steady-state path on a properly-upgraded v3 node.
func TestAutoMigrateLegacyOverlayKeys_AlreadyMigrated(t *testing.T) {
	dir := t.TempDir()
	db, err := leveldb.OpenFile(filepath.Join(dir, "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Three legacy keys + three v3 keys → counts match → skip migrate.
	for _, k := range []string{
		"ovl:tm_uhrp:txid1:0",
		"ovl:tm_uhrp:txid2:0",
		"ovl:tm_uhrp:txid3:0",
		"ovl3:tm_uhrp:txid1:0",
		"ovl3:tm_uhrp:txid2:0",
		"ovl3:tm_uhrp:txid3:0",
	} {
		if err := db.Put([]byte(k), []byte("x"), nil); err != nil {
			t.Fatal(err)
		}
	}

	if err := autoMigrateLegacyOverlayKeys(db, nil); err != nil {
		t.Fatalf("expected nil error on already-migrated, got: %v", err)
	}
}

// TestAutoMigrateLegacyOverlayKeys_UnparseableLegacyFailsBoot verifies
// the safety contract: legacy keys that don't fit the
// `ovl:<topic>:<txid>:<vout>` shape cause a non-nil return, which
// surfaces to main.go as a log.Fatal. We MUST NOT silently let a
// daemon boot on partially-corrupt v2 data.
func TestAutoMigrateLegacyOverlayKeys_UnparseableLegacyFailsBoot(t *testing.T) {
	dir := t.TempDir()
	db, err := leveldb.OpenFile(filepath.Join(dir, "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// One legacy key with a malformed shape (only 3 colon-separated
	// segments instead of 4): topic, txid — no vout. Migrator should
	// flag this as UnparseableKey > 0 and we should surface as error.
	if err := db.Put([]byte("ovl:bogus"), []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}

	err = autoMigrateLegacyOverlayKeys(db, nil)
	if err == nil {
		t.Fatal("expected non-nil error on unparseable legacy data, got nil")
	}
}
