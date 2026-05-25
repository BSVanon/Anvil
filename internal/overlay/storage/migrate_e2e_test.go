package storage_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/legacyshim"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// seedLegacyUHRPEntry writes a legacy `ovl:<topic>:<txid>:<vout>` JSON
// entry that mirrors what Anvil v2.x.x produced for an admitted UHRP
// output. Returns the outpoint for later assertions.
func seedLegacyUHRPEntry(t *testing.T, db *leveldb.DB, txidHex, contentHash, url string, vout uint32) *transaction.Outpoint {
	t.Helper()
	uhrpEntry := topics.UHRPEntry{
		ContentHash: contentHash,
		URL:         url,
		ContentType: "image/png",
	}
	uhrpEntryJSON, _ := json.Marshal(&uhrpEntry)
	legacyKey := fmt.Sprintf("ovl:%s:%s:%d", topics.UHRPTopicName, txidHex, vout)
	legacyJSON, _ := json.Marshal(map[string]any{
		"txid":     txidHex,
		"vout":     vout,
		"topic":    topics.UHRPTopicName,
		"satoshis": 1,
		"metadata": json.RawMessage(uhrpEntryJSON),
	})
	if err := db.Put([]byte(legacyKey), legacyJSON, nil); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	h, _ := chainhash.NewHashFromHex(txidHex)
	return &transaction.Outpoint{Txid: *h, Index: vout}
}

// buildAndSeedUHRPBEEF constructs a real one-output UHRP tx, wraps it
// in BEEF, writes the BEEF bytes under `beef3:<txid>` (simulating what
// a future BEEF-fetch workstream would do during migration), and
// returns the tx's txid hex so seedLegacyUHRPEntry can write a
// matching legacy record.
func buildAndSeedUHRPBEEF(t *testing.T, db *leveldb.DB, contentHash string) string {
	t.Helper()
	hashBytes, _ := hex.DecodeString(contentHash)
	scriptBytes := []byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}
	scriptBytes = append(scriptBytes, []byte(topics.UHRPProtocolID)...)
	scriptBytes = append(scriptBytes, byte(len(hashBytes)))
	scriptBytes = append(scriptBytes, hashBytes...)

	tx := transaction.NewTransaction()
	s := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &s, Satoshis: 0})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	beefBytes, err := beef.Bytes()
	if err != nil {
		t.Fatalf("beef.Bytes: %v", err)
	}
	txid := tx.TxID()
	if err := db.Put([]byte("beef3:"+txid.String()), beefBytes, nil); err != nil {
		t.Fatalf("seed beef3: %v", err)
	}
	return txid.String()
}

// newE2EDB opens a fresh LevelDB the e2e tests share across helpers.
func newE2EDB(t *testing.T) *leveldb.DB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newE2EEngine wires a real v3engine against the supplied LevelDB so
// the tests exercise the production query path.
func newE2EEngine(t *testing.T, db *leveldb.DB) (*v3engine.Handlers, *legacyshim.Shim) {
	t.Helper()
	hdr, err := headers.NewTestStore(filepath.Join(t.TempDir(), "hdr"))
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	t.Cleanup(func() { _ = hdr.Close() })
	eng, err := v3engine.New(&v3engine.Config{
		Storage:      storage.New(db),
		HeadersStore: hdr,
		LookupDB:     db,
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	h := v3engine.NewHandlers(eng)
	shim := &legacyshim.Shim{
		Engine:        eng,
		Parsers:       legacyshim.DefaultParsers(),
		ServiceTopics: legacyshim.DefaultServiceTopics(),
	}
	return h, shim
}

// TestMigrate_EndToEnd_LookupBackfillLandsInIndexes is the end-to-end
// test Codex review 09ddf00c90061eac asked for: seed legacy UHRP,
// migrate with the LookupBackfiller wired to a real canonical lookup
// service, and assert the lk_uhrp:* indexes are populated (so the
// lookup service answers with formulas — which it doesn't do without
// the backfill).
//
// Also asserts the documented BEEF-empty post-migration limitation:
// the canonical engine.Lookup path drops migrated records at
// hydration because beef3 is empty. That's the gap a future
// BEEF-fetch workstream closes; this test pins the current behaviour
// so it can't regress silently.
func TestMigrate_EndToEnd_LookupBackfillLandsInIndexes(t *testing.T) {
	db := newE2EDB(t)
	const txidHex = "1212121212121212121212121212121212121212121212121212121212121212"
	const contentHash = "abababababababababababababababababababababababababababababababab"
	seedLegacyUHRPEntry(t, db, txidHex, contentHash, "https://example.test/migrated", 0)

	uhrp := lookups.NewUHRPLookupService(db)
	stats, err := storage.Migrate(context.Background(), db, storage.MigrateOptions{
		LookupBackfiller: func(topic string, op *transaction.Outpoint, metadata json.RawMessage) error {
			if topic == topics.UHRPTopicName {
				return uhrp.BackfillFromLegacyMetadata(op, metadata)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if stats.Migrated != 1 {
		t.Fatalf("Migrated = %d, want 1", stats.Migrated)
	}
	if stats.LookupBackfilled != 1 {
		t.Fatalf("LookupBackfilled = %d, want 1", stats.LookupBackfilled)
	}

	// Assertion 1: lookup-service direct query returns the formula.
	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: contentHash})
	answer, err := uhrp.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.UHRPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("uhrp.Lookup direct: %v", err)
	}
	if answer == nil || len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula from direct lookup, got %+v", answer)
	}
	if answer.Formulas[0].Outpoint == nil || answer.Formulas[0].Outpoint.Txid.String() != txidHex {
		t.Fatalf("formula outpoint mismatch: %+v", answer.Formulas[0].Outpoint)
	}

	// Assertion 2: canonical engine.Lookup drops the record at
	// hydration (BEEF-empty limitation). Documented in operator docs
	// + W-8 release notes.
	_, shim := newE2EEngine(t, db)
	// Use the shim's underlying engine via a parallel call to prove
	// the path; legacyshim wraps the engine and behaves identically
	// for the hydration question.
	srv := httptest.NewServer(handlerForShim(shim))
	t.Cleanup(srv.Close)

	question, _ := json.Marshal(map[string]any{
		"service": topics.UHRPLookupServiceName,
		"query":   topics.UHRPLookupQuery{ContentHash: contentHash},
	})
	resp, err := http.Post(srv.URL+"/overlay/query", "application/json", bytes.NewReader(question))
	if err != nil {
		t.Fatalf("POST /overlay/query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var legacyResp struct {
		Type    string          `json:"type"`
		Outputs []json.RawMessage `json:"outputs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&legacyResp); err != nil {
		t.Fatalf("decode legacy resp: %v", err)
	}
	if len(legacyResp.Outputs) != 0 {
		t.Fatalf("expected 0 outputs (BEEF-empty migrated record dropped by engine hydration), got %d", len(legacyResp.Outputs))
	}
}

// TestMigrate_EndToEnd_WithBEEF_LookupReturnsRecord seeds a legacy
// record AND a corresponding beef3 entry (simulating a future
// BEEF-fetch workstream), runs migration with backfill, and asserts
// canonical /lookup + legacyshim /overlay/query both return the
// migrated record now that BEEF is present. This proves the lk_*
// backfill is wired correctly and the BEEF-empty case is the ONLY
// remaining gap.
func TestMigrate_EndToEnd_WithBEEF_LookupReturnsRecord(t *testing.T) {
	db := newE2EDB(t)
	const contentHash = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	txidHex := buildAndSeedUHRPBEEF(t, db, contentHash)
	seedLegacyUHRPEntry(t, db, txidHex, contentHash, "https://example.test/with-beef", 0)

	uhrp := lookups.NewUHRPLookupService(db)
	if _, err := storage.Migrate(context.Background(), db, storage.MigrateOptions{
		LookupBackfiller: func(topic string, op *transaction.Outpoint, md json.RawMessage) error {
			if topic == topics.UHRPTopicName {
				return uhrp.BackfillFromLegacyMetadata(op, md)
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	handlers, shim := newE2EEngine(t, db)

	// Canonical /lookup path
	mux := http.NewServeMux()
	handlers.Register(mux, nil)
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	question, _ := json.Marshal(map[string]any{
		"service": topics.UHRPLookupServiceName,
		"query":   topics.UHRPLookupQuery{ContentHash: contentHash},
	})
	resp, err := http.Post(srv.URL+"/lookup", "application/json", bytes.NewReader(question))
	if err != nil {
		t.Fatalf("POST /lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/lookup status %d", resp.StatusCode)
	}
	var canonAnswer struct {
		Type    string `json:"type"`
		Outputs []struct {
			Beef        []byte `json:"beef"`
			OutputIndex int    `json:"outputIndex"`
		} `json:"outputs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&canonAnswer); err != nil {
		t.Fatalf("decode canonical: %v", err)
	}
	if len(canonAnswer.Outputs) != 1 {
		t.Fatalf("canonical /lookup expected 1 output (BEEF present), got %d", len(canonAnswer.Outputs))
	}
	if len(canonAnswer.Outputs[0].Beef) == 0 {
		t.Fatalf("canonical /lookup output missing BEEF bytes")
	}

	// Legacy /overlay/query path — proves the shim's metadata
	// reconstruction also works for migrated records when BEEF is
	// present.
	resp2, err := http.Post(srv.URL+"/overlay/query", "application/json", bytes.NewReader(question))
	if err != nil {
		t.Fatalf("POST /overlay/query: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("/overlay/query status %d", resp2.StatusCode)
	}
	var legacyAnswer struct {
		Type    string `json:"type"`
		Outputs []struct {
			Txid     string          `json:"txid"`
			Vout     int             `json:"vout"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"outputs"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&legacyAnswer); err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if len(legacyAnswer.Outputs) != 1 {
		t.Fatalf("legacy /overlay/query expected 1 output, got %d", len(legacyAnswer.Outputs))
	}
	if legacyAnswer.Outputs[0].Txid != txidHex {
		t.Fatalf("legacy output txid mismatch: %s vs %s", legacyAnswer.Outputs[0].Txid, txidHex)
	}
	var roundTrip topics.UHRPEntry
	if err := json.Unmarshal(legacyAnswer.Outputs[0].Metadata, &roundTrip); err != nil {
		t.Fatalf("decode reconstructed metadata: %v", err)
	}
	if roundTrip.ContentHash != contentHash {
		t.Fatalf("reconstructed content_hash mismatch")
	}
}

// handlerForShim is a tiny test-only adapter that mounts a single
// shim's routes on a fresh mux so the BEEF-empty test can exercise
// /overlay/query without also bringing up the canonical handlers.
func handlerForShim(s *legacyshim.Shim) http.Handler {
	mux := http.NewServeMux()
	s.Register(mux, nil)
	return mux
}
