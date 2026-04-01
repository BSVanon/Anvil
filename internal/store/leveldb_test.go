package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// TestOpenWithRecover_Clean verifies that a healthy database opens normally.
func TestOpenWithRecover_Clean(t *testing.T) {
	dir := t.TempDir()

	db, err := OpenWithRecover(dir, nil)
	if err != nil {
		t.Fatalf("open clean db: %v", err)
	}

	// Write and read back
	if err := db.Put([]byte("k"), []byte("v"), nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := db.Get([]byte("k"), nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("expected 'v', got %q", got)
	}
	db.Close()

	// Reopen — should succeed without recovery
	db2, err := OpenWithRecover(dir, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err = db2.Get([]byte("k"), nil)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("expected 'v' after reopen, got %q", got)
	}
	db2.Close()
}

// TestOpenWithRecover_Corrupted simulates LevelDB corruption by writing
// garbage into the MANIFEST file, then verifies that OpenWithRecover
// recovers the database and previously-written data survives.
func TestOpenWithRecover_Corrupted(t *testing.T) {
	dir := t.TempDir()

	// Phase 1: create a healthy database with data
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	for i := 0; i < 100; i++ {
		key := []byte("key-" + string(rune('A'+i%26)))
		if err := db.Put(key, []byte("value"), nil); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
	}
	// Force compaction so data lives in .ldb files, not just the WAL
	if err := db.CompactRange(util.Range{}); err != nil {
		t.Fatalf("compact: %v", err)
	}
	db.Close()

	// Phase 2: corrupt the MANIFEST file — this is the most common
	// corruption vector after unclean shutdown. LevelDB records the
	// active .ldb file set in the MANIFEST; corrupting it makes OpenFile
	// return ErrCorrupted.
	manifests, _ := filepath.Glob(filepath.Join(dir, "MANIFEST-*"))
	if len(manifests) == 0 {
		t.Fatal("no MANIFEST file found — can't simulate corruption")
	}
	for _, m := range manifests {
		if err := os.WriteFile(m, []byte("corrupted garbage data"), 0644); err != nil {
			t.Fatalf("corrupt MANIFEST: %v", err)
		}
	}

	// Verify that a plain OpenFile fails
	_, err = leveldb.OpenFile(dir, nil)
	if err == nil {
		t.Fatal("expected OpenFile to fail on corrupted MANIFEST, but it succeeded")
	}
	t.Logf("plain OpenFile error (expected): %v", err)

	// Phase 3: OpenWithRecover should handle the corruption
	db2, err := OpenWithRecover(dir, nil)
	if err != nil {
		t.Fatalf("OpenWithRecover failed: %v", err)
	}
	defer db2.Close()

	// Phase 4: verify at least some data survived recovery
	// RecoverFile rebuilds the MANIFEST from .ldb files, so compacted
	// data should be intact. WAL-only data may be lost — that's expected.
	recovered := 0
	iter := db2.NewIterator(nil, nil)
	for iter.Next() {
		recovered++
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}

	if recovered == 0 {
		t.Fatal("recovery produced zero entries — expected at least some data to survive")
	}
	t.Logf("recovered %d entries after MANIFEST corruption", recovered)

	// Verify the database is writable after recovery
	if err := db2.Put([]byte("post-recovery"), []byte("works"), nil); err != nil {
		t.Fatalf("post-recovery write: %v", err)
	}
	got, err := db2.Get([]byte("post-recovery"), nil)
	if err != nil {
		t.Fatalf("post-recovery read: %v", err)
	}
	if string(got) != "works" {
		t.Fatalf("expected 'works', got %q", got)
	}
}

// TestOpenWithRecover_MissingDir verifies that a nonexistent path creates
// a fresh database (not a recovery attempt).
func TestOpenWithRecover_MissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")

	db, err := OpenWithRecover(dir, nil)
	if err != nil {
		t.Fatalf("open missing dir: %v", err)
	}
	defer db.Close()

	if err := db.Put([]byte("fresh"), []byte("db"), nil); err != nil {
		t.Fatalf("write to fresh db: %v", err)
	}
}
