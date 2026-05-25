package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// seedLegacyOutput writes a legacy `ovl:<topic>:<txid>:<vout>` JSON
// entry directly into the LevelDB, matching the on-disk shape Anvil
// v2.x.x produced. Used by every migration test as the source data.
func seedLegacyOutput(t *testing.T, db *leveldb.DB, topic string, txidSeed byte, vout uint32, spent bool) {
	t.Helper()
	txid := makeHash(txidSeed)
	key := fmt.Sprintf("%s%s:%s:%d", legacyOutputPrefix, topic, txid.String(), vout)
	value := legacyAdmittedOutput{
		Txid:         txid.String(),
		Vout:         int(vout),
		Topic:        topic,
		OutputScript: []byte{0x00, 0x6a},
		Satoshis:     42,
		Metadata:     json.RawMessage(`{"k":"v"}`),
		Spent:        spent,
	}
	body, err := json.Marshal(&value)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := db.Put([]byte(key), body, nil); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}
}

func newMigrationDB(t *testing.T) *leveldb.DB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestMigrate_HappyPath verifies the migration converts legacy
// records into v3 records that the canonical Storage methods can read.
func TestMigrate_HappyPath(t *testing.T) {
	db := newMigrationDB(t)
	seedLegacyOutput(t, db, "tm_uhrp", 0x11, 0, false)
	seedLegacyOutput(t, db, "tm_uhrp", 0x11, 1, false)
	seedLegacyOutput(t, db, "tm_dex_swap", 0x22, 0, true) // spent — should NOT be in topi3

	stats, err := Migrate(context.Background(), db, MigrateOptions{
		Clock: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if stats.LegacyKeysSeen != 3 {
		t.Fatalf("LegacyKeysSeen = %d, want 3", stats.LegacyKeysSeen)
	}
	if stats.Migrated != 3 {
		t.Fatalf("Migrated = %d, want 3", stats.Migrated)
	}
	if stats.AlreadyMigrated != 0 || stats.UnparseableLegacy != 0 || stats.UnparseableKey != 0 {
		t.Fatalf("expected zero skip counts, got %+v", stats)
	}

	// v3 Storage should now find the unspent UHRP records via the
	// canonical FindUTXOsForTopic path.
	s := New(db)
	op := &transaction.Outpoint{Txid: *makeHash(0x11), Index: 0}
	topic := "tm_uhrp"
	out, err := s.FindOutput(context.Background(), op, &topic, nil, false)
	if err != nil {
		t.Fatalf("FindOutput post-migration: %v", err)
	}
	if out.Topic != topic || out.Outpoint.Index != 0 {
		t.Fatalf("unexpected v3 record: %+v", out)
	}
	if out.MerkleState != engine.MerkleStateUnmined {
		t.Fatalf("expected MerkleStateUnmined, got %v", out.MerkleState)
	}

	// Unspent UHRP records should appear in FindUTXOsForTopic.
	utxos, err := s.FindUTXOsForTopic(context.Background(), topic, 0, 0, false)
	if err != nil {
		t.Fatalf("FindUTXOsForTopic: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("expected 2 unspent UHRP UTXOs, got %d", len(utxos))
	}

	// The spent DEX-swap record should NOT appear in FindUTXOsForTopic
	// (topi3 skipped during migration for spent entries).
	dexUTXOs, err := s.FindUTXOsForTopic(context.Background(), "tm_dex_swap", 0, 0, false)
	if err != nil {
		t.Fatalf("FindUTXOsForTopic dex: %v", err)
	}
	if len(dexUTXOs) != 0 {
		t.Fatalf("spent DEX record should not appear in UTXO scan, got %d", len(dexUTXOs))
	}

	// But it should be findable by spent-filter on FindOutput.
	dexOp := &transaction.Outpoint{Txid: *makeHash(0x22), Index: 0}
	dexTopic := "tm_dex_swap"
	spentTrue := true
	dexRec, err := s.FindOutput(context.Background(), dexOp, &dexTopic, &spentTrue, false)
	if err != nil {
		t.Fatalf("FindOutput spent=true: %v", err)
	}
	if !dexRec.Spent {
		t.Fatalf("expected spent record, got Spent=%v", dexRec.Spent)
	}
}

// TestMigrate_IdempotentReRun verifies running the migration twice is
// safe and the second run is a no-op.
func TestMigrate_IdempotentReRun(t *testing.T) {
	db := newMigrationDB(t)
	seedLegacyOutput(t, db, "tm_uhrp", 0x33, 0, false)
	seedLegacyOutput(t, db, "tm_uhrp", 0x33, 1, false)

	first, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if first.Migrated != 2 {
		t.Fatalf("first run Migrated = %d, want 2", first.Migrated)
	}

	second, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if second.Migrated != 0 {
		t.Fatalf("second run should re-migrate 0, got %d", second.Migrated)
	}
	if second.AlreadyMigrated != 2 {
		t.Fatalf("second run AlreadyMigrated = %d, want 2", second.AlreadyMigrated)
	}
	if second.LegacyKeysSeen != 2 {
		t.Fatalf("second run LegacyKeysSeen = %d, want 2", second.LegacyKeysSeen)
	}
}

// TestMigrate_DryRun walks the entries and reports counts without
// writing v3 keys.
func TestMigrate_DryRun(t *testing.T) {
	db := newMigrationDB(t)
	seedLegacyOutput(t, db, "tm_uhrp", 0x44, 0, false)

	stats, err := Migrate(context.Background(), db, MigrateOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if stats.Migrated != 1 || stats.LegacyKeysSeen != 1 {
		t.Fatalf("dry-run stats unexpected: %+v", stats)
	}

	// No v3 record should be written.
	op := &transaction.Outpoint{Txid: *makeHash(0x44), Index: 0}
	topic := "tm_uhrp"
	if _, err := New(db).FindOutput(context.Background(), op, &topic, nil, false); err != engine.ErrNotFound {
		t.Fatalf("expected ErrNotFound (dry-run wrote nothing), got %v", err)
	}
}

// TestMigrate_EmptySource: zero legacy entries → zero migrations.
func TestMigrate_EmptySource(t *testing.T) {
	db := newMigrationDB(t)
	stats, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate empty: %v", err)
	}
	if stats != (MigrateStats{}) {
		t.Fatalf("expected zero stats, got %+v", stats)
	}
}

// TestMigrate_UnparseableLegacyValue: a corrupt JSON value at a
// legacy key is counted, not fatal.
func TestMigrate_UnparseableLegacyValue(t *testing.T) {
	db := newMigrationDB(t)
	txidStr := "11" + string(make([]byte, 0))
	for i := 0; i < 31; i++ {
		txidStr += "11"
	}
	if err := db.Put([]byte("ovl:tm_uhrp:"+txidStr+":0"), []byte("not-json{{"), nil); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	stats, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if stats.UnparseableLegacy != 1 || stats.Migrated != 0 {
		t.Fatalf("expected 1 unparseable + 0 migrated, got %+v", stats)
	}
}

// TestMigrate_UnparseableLegacyKey: a key that doesn't fit the
// expected shape is counted and skipped.
func TestMigrate_UnparseableLegacyKey(t *testing.T) {
	db := newMigrationDB(t)
	// Wrong shape: missing the txid + vout segments.
	if err := db.Put([]byte("ovl:tm_uhrp"), []byte("{}"), nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stats, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if stats.UnparseableKey != 1 || stats.Migrated != 0 {
		t.Fatalf("expected 1 unparseable-key + 0 migrated, got %+v", stats)
	}
}

// TestMigrate_ContextCancellationStopsEarly verifies the migration
// respects ctx.Done() between records.
func TestMigrate_ContextCancellationStopsEarly(t *testing.T) {
	db := newMigrationDB(t)
	for i := 0; i < 5; i++ {
		seedLegacyOutput(t, db, "tm_uhrp", byte(0x60+i), 0, false)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	stats, err := Migrate(ctx, db, MigrateOptions{})
	if err == nil {
		t.Fatalf("expected ctx error, got nil")
	}
	if stats.Migrated > 0 {
		t.Fatalf("expected 0 migrated after immediate cancel, got %d", stats.Migrated)
	}
}

// TestMigrate_ParseLegacyKey_Edge cases — explicit per-shape coverage
// for parseLegacyOutputKey since the migration relies on it for
// data integrity.
func TestMigrate_ParseLegacyKey_Edge(t *testing.T) {
	type tc struct {
		name      string
		key       string
		wantTopic string
		wantVout  uint32
		wantOk    bool
	}
	txidHex := ""
	for i := 0; i < 32; i++ {
		txidHex += "ab"
	}
	cases := []tc{
		{"valid simple", "ovl:tm_uhrp:" + txidHex + ":0", "tm_uhrp", 0, true},
		{"valid larger vout", "ovl:tm_dex_swap:" + txidHex + ":12345", "tm_dex_swap", 12345, true},
		{"valid topic with underscores", "ovl:tm_ordlock_listings:" + txidHex + ":7", "tm_ordlock_listings", 7, true},
		{"no prefix", "noprefix", "", 0, false},
		{"no vout", "ovl:tm_uhrp:" + txidHex, "", 0, false},
		{"vout not numeric", "ovl:tm_uhrp:" + txidHex + ":abc", "", 0, false},
		{"txid not 64 chars", "ovl:tm_uhrp:0102:0", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			topic, _, vout, ok := parseLegacyOutputKey([]byte(c.key))
			if ok != c.wantOk {
				t.Fatalf("ok = %v, want %v", ok, c.wantOk)
			}
			if c.wantOk {
				if topic != c.wantTopic {
					t.Fatalf("topic = %q, want %q", topic, c.wantTopic)
				}
				if vout != c.wantVout {
					t.Fatalf("vout = %d, want %d", vout, c.wantVout)
				}
			}
		})
	}
}

// TestMigrate_Repair_BackfillRunsOnAlreadyMigratedRecords pins the
// behaviour Codex review 9730ed97b8e75d6c demanded: a rerun must
// repair lookup-side state for records whose storage primary already
// exists. Without this, a node that ran the pre-fix RC migrator (no
// LookupBackfiller) could never recover its lk_* indexes by rerunning
// the fixed migrator.
//
// Flow: seed legacy → migrate WITHOUT LookupBackfiller (simulates the
// pre-fix RC run) → verify storage has the records but lookup
// backfiller was never invoked → migrate AGAIN WITH a recording
// LookupBackfiller → verify Migrated=0 + AlreadyMigrated=N +
// LookupBackfilled=N + the backfiller was actually invoked for every
// record.
func TestMigrate_Repair_BackfillRunsOnAlreadyMigratedRecords(t *testing.T) {
	db := newMigrationDB(t)
	seedLegacyOutput(t, db, "tm_uhrp", 0xA1, 0, false)
	seedLegacyOutput(t, db, "tm_uhrp", 0xA1, 1, false)
	seedLegacyOutput(t, db, "tm_dex_swap", 0xA2, 0, false)

	// First pass: storage-only migration (no LookupBackfiller).
	// Mirrors the pre-fix RC migrator's behaviour.
	first, err := Migrate(context.Background(), db, MigrateOptions{})
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if first.Migrated != 3 {
		t.Fatalf("first run Migrated = %d, want 3", first.Migrated)
	}
	if first.LookupBackfilled != 0 {
		t.Fatalf("first run LookupBackfilled = %d, want 0 (no backfiller wired)", first.LookupBackfilled)
	}

	// Second pass: repair rerun WITH a LookupBackfiller. The
	// canonical lk_* indexes were never populated; this pass must
	// retroactively call the backfiller for every record even
	// though Migrated=0.
	type seen struct {
		topic    string
		outpoint string
	}
	var calls []seen
	second, err := Migrate(context.Background(), db, MigrateOptions{
		LookupBackfiller: func(topic string, op *transaction.Outpoint, metadata json.RawMessage) error {
			calls = append(calls, seen{topic: topic, outpoint: fmt.Sprintf("%s.%d", op.Txid.String(), op.Index)})
			return nil
		},
	})
	if err != nil {
		t.Fatalf("repair migrate: %v", err)
	}
	if second.Migrated != 0 {
		t.Fatalf("repair run Migrated = %d, want 0 (storage was already done)", second.Migrated)
	}
	if second.AlreadyMigrated != 3 {
		t.Fatalf("repair run AlreadyMigrated = %d, want 3", second.AlreadyMigrated)
	}
	if second.LookupBackfilled != 3 {
		t.Fatalf("repair run LookupBackfilled = %d, want 3 (must run on already-migrated)", second.LookupBackfilled)
	}
	if len(calls) != 3 {
		t.Fatalf("LookupBackfiller called %d times, want 3", len(calls))
	}
	// Verify every record was actually dispatched (topics + outpoints).
	wantTopics := map[string]int{"tm_uhrp": 2, "tm_dex_swap": 1}
	gotTopics := map[string]int{}
	for _, c := range calls {
		gotTopics[c.topic]++
	}
	for topic, want := range wantTopics {
		if gotTopics[topic] != want {
			t.Fatalf("topic %q called %d times, want %d", topic, gotTopics[topic], want)
		}
	}
}

// TestMigrate_Repair_RetriesFailedLookupBackfill: when the first
// pass's LookupBackfiller returns an error for a record (e.g.
// transient LevelDB issue, parser regression), a subsequent pass
// MUST retry that record's backfill rather than skipping it because
// the storage primary already exists.
func TestMigrate_Repair_RetriesFailedLookupBackfill(t *testing.T) {
	db := newMigrationDB(t)
	seedLegacyOutput(t, db, "tm_uhrp", 0xB1, 0, false)
	seedLegacyOutput(t, db, "tm_uhrp", 0xB1, 1, false)

	// First pass: LookupBackfiller fails for every record.
	first, err := Migrate(context.Background(), db, MigrateOptions{
		LookupBackfiller: func(topic string, op *transaction.Outpoint, metadata json.RawMessage) error {
			return fmt.Errorf("simulated transient lookup-side failure for %s", op.Txid.String())
		},
	})
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if first.Migrated != 2 {
		t.Fatalf("first run Migrated = %d, want 2", first.Migrated)
	}
	if first.LookupBackfilled != 0 || first.LookupBackfillErrors != 2 {
		t.Fatalf("first run lookup stats unexpected: %+v", first)
	}

	// Second pass: backfiller succeeds. Storage records exist but
	// lookup-side state is broken — the rerun must repair it.
	var calls int
	second, err := Migrate(context.Background(), db, MigrateOptions{
		LookupBackfiller: func(topic string, op *transaction.Outpoint, metadata json.RawMessage) error {
			calls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("retry migrate: %v", err)
	}
	if second.AlreadyMigrated != 2 {
		t.Fatalf("retry AlreadyMigrated = %d, want 2", second.AlreadyMigrated)
	}
	if second.LookupBackfilled != 2 {
		t.Fatalf("retry LookupBackfilled = %d, want 2 (must retry previously-failed records)", second.LookupBackfilled)
	}
	if second.LookupBackfillErrors != 0 {
		t.Fatalf("retry should have 0 errors, got %d", second.LookupBackfillErrors)
	}
	if calls != 2 {
		t.Fatalf("LookupBackfiller called %d times on retry, want 2", calls)
	}
}

// strconv kept live in case future tests grow.
var _ = strconv.Itoa
