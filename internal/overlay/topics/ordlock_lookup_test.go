package topics

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay"
	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Pure-helper tests (no engine) ---

func TestMatchesOrdLockQuery(t *testing.T) {
	bsv21 := OrdLockEntry{Protocol: "bsv-21", TokenId: "abc123_0", CancelPkhHex: "ab" + strings.Repeat("00", 19)}
	bsv20 := OrdLockEntry{Protocol: "bsv-20", Tick: "MNEE", CancelPkhHex: "cd" + strings.Repeat("00", 19)}

	tests := []struct {
		name                  string
		entry                 OrdLockEntry
		tokenId, tick, cancel string
		want                  bool
	}{
		{"all-empty matches anything", bsv21, "", "", "", true},
		{"tokenId match", bsv21, "abc123_0", "", "", true},
		{"tokenId case-insensitive match", bsv21, "ABC123_0", "", "", true},
		{"tokenId mismatch", bsv21, "deadbeef_0", "", "", false},
		{"tick match", bsv20, "", "MNEE", "", true},
		{"tick mismatch", bsv20, "", "BSV", "", false},
		{"tokenId and tick mutually exclusive — tokenId wins", bsv21, "abc123_0", "MNEE", "", true},
		{"cancel match (lowercase)", bsv20, "", "", "cd" + strings.Repeat("00", 19), true},
		{"cancel match (mixed case)", bsv20, "", "", "Cd" + strings.Repeat("00", 19), true},
		{"cancel mismatch", bsv20, "", "", "ee" + strings.Repeat("00", 19), false},
		{"tokenId AND cancel both required", bsv21, "abc123_0", "", "ab" + strings.Repeat("00", 19), true},
		{"tokenId match but cancel mismatch fails", bsv21, "abc123_0", "", "ee" + strings.Repeat("00", 19), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesOrdLockQuery(tc.entry, tc.tokenId, strings.ToUpper(tc.tick), strings.ToLower(tc.cancel))
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeCancelFilter(t *testing.T) {
	t.Run("empty input → empty filter", func(t *testing.T) {
		got, err := normalizeCancelFilter("")
		if err != nil || got != "" {
			t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})
	t.Run("valid mainnet address → 20-byte pkh hex", func(t *testing.T) {
		// Derive a known address from a known pkh and round-trip it.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		addr, _ := script.NewAddressFromPublicKeyHash(pkh, true)
		got, err := normalizeCancelFilter(addr.AddressString)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "28672b084a32711ee267c1e61f49771784620e9f" {
			t.Errorf("got pkh hex %q, want %q", got, "28672b084a32711ee267c1e61f49771784620e9f")
		}
	})
	t.Run("garbage input → error", func(t *testing.T) {
		if _, err := normalizeCancelFilter("not-an-address"); err == nil {
			t.Error("expected error on garbage address")
		}
	})
	t.Run("testnet address → error (mainnet-only surface)", func(t *testing.T) {
		// Build a testnet P2PKH (version 0x6f) for a known pkh and confirm
		// the lookup rejects it instead of silently matching on the bare pkh.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		testnetAddr, _ := script.NewAddressFromPublicKeyHash(pkh, false)
		_, err := normalizeCancelFilter(testnetAddr.AddressString)
		if err == nil {
			t.Errorf("testnet cancelAddress %q must be rejected on this mainnet-only surface", testnetAddr.AddressString)
		}
	})
	t.Run("mainnet-looking address with bad checksum → error", func(t *testing.T) {
		// Take a valid mainnet address, decode it, corrupt the trailing
		// checksum byte, re-encode, and confirm the filter rejects it.
		// Without checksum validation a payload like this would pass the
		// length + version checks and silently match listings by bare pkh.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		good, _ := script.NewAddressFromPublicKeyHash(pkh, true)
		raw, err := base58.Decode(good.AddressString)
		if err != nil {
			t.Fatalf("decode good address: %v", err)
		}
		raw[len(raw)-1] ^= 0xff // flip last checksum byte
		corrupted := base58.Encode(raw)
		if _, err := normalizeCancelFilter(corrupted); err == nil {
			t.Errorf("bad-checksum address %q must be rejected", corrupted)
		}
	})
}

func TestNormalizeLimitOffset(t *testing.T) {
	tests := []struct{ inL, inO, wantL, wantO int }{
		{0, 0, 100, 0},
		{50, 25, 50, 25},
		{1000, 0, 500, 0},
		{-5, -5, 100, 0},
		{500, 0, 500, 0},
	}
	for _, tc := range tests {
		gotL, gotO := normalizeLimitOffset(tc.inL, tc.inO)
		if gotL != tc.wantL || gotO != tc.wantO {
			t.Errorf("normalizeLimitOffset(%d,%d) = (%d,%d), want (%d,%d)", tc.inL, tc.inO, gotL, gotO, tc.wantL, tc.wantO)
		}
	}
}

func TestOrdLockLookupService_DocMetadata(t *testing.T) {
	ls := NewOrdLockLookupService(nil)
	if ls.GetDocumentation() == "" {
		t.Error("expected non-empty documentation")
	}
	meta := ls.GetMetadata()
	if meta["service"] != OrdLockLookupServiceName {
		t.Errorf("service=%v, want %s", meta["service"], OrdLockLookupServiceName)
	}
}

func TestOrdLockLookupService_InvalidQueryReturnsError(t *testing.T) {
	ls := NewOrdLockLookupService(nil)
	if _, err := ls.Lookup(json.RawMessage(`{malformed`)); err == nil {
		t.Fatal("expected error on malformed query JSON")
	}
}

func TestOrdLockLookupService_InvalidCancelAddressReturnsError(t *testing.T) {
	ls := NewOrdLockLookupService(nil)
	_, err := ls.Lookup(json.RawMessage(`{"cancelAddress":"not-an-address"}`))
	if err == nil {
		t.Fatal("expected error on invalid cancelAddress")
	}
}

// --- Engine-backed integration test ---

// admitOrdLockToEngine is a helper that builds an OrdLock listing tx, submits
// it through the engine, and returns the txid + the AdmittedAt timestamp the
// engine recorded.
func admitOrdLockToEngine(t *testing.T, engine *overlay.Engine, scr *script.Script) string {
	t.Helper()
	tx := transaction.NewTransaction()
	// Make each tx unique so they hash differently.
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(time.Now().UnixNano() >> uint(i))
	}
	hash, _ := chainhash.NewHash(salt)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       hash,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: scr})
	if _, err := engine.Submit(tx.Bytes(), []string{OrdLockTopicName}); err != nil {
		t.Fatalf("engine.Submit: %v", err)
	}
	return tx.TxID().String()
}

func newTestEngine(t *testing.T) *overlay.Engine {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-ordlock-lookup-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	engine := overlay.NewEngine(db, nil)
	engine.RegisterTopic(OrdLockTopicName, NewOrdLockTopicManager())
	engine.RegisterLookup(OrdLockLookupServiceName, NewOrdLockLookupService(engine), []string{OrdLockTopicName})
	return engine
}

// TestOrdLockLookup_AllReturnsAll walks the full lifecycle: admit several
// listings, query "list:all", get them all back.
func TestOrdLockLookup_AllReturnsAll(t *testing.T) {
	engine := newTestEngine(t)
	for i := 0; i < 3; i++ {
		scr := buildOrdLockScriptForTest(t,
			map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": fmt.Sprintf("T%03d", i)},
			fillPkh(byte(i)), fillPkh(byte(0xa0+i)), uint64(100+i))
		admitOrdLockToEngine(t, engine, scr)
		// Sleep so AdmittedAt timestamps differ in 1-second resolution.
		time.Sleep(1100 * time.Millisecond)
	}

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 3 {
		t.Errorf("expected 3 outputs, got %d", len(answer.Outputs))
	}
}

// TestOrdLockLookup_FilterByTokenId narrows the result set to one BSV-21.
func TestOrdLockLookup_FilterByTokenId(t *testing.T) {
	engine := newTestEngine(t)
	// Admit two BSV-20 entries and the real BSV-21 fixture.
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "AAAA"},
		fillPkh(0x01), fillPkh(0x02), 1))
	admitOrdLockToEngine(t, engine, scriptFromHex(t, fixtureBSV21TVZNScriptHex))
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "BBBB"},
		fillPkh(0x03), fillPkh(0x04), 2))

	q := fmt.Sprintf(`{"tokenId":"%s"}`, fixtureBSV21TVZNTokenId)
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(q),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 BSV-21 hit, got %d", len(answer.Outputs))
	}
	var entry OrdLockEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)
	if entry.TokenId != fixtureBSV21TVZNTokenId {
		t.Errorf("got tokenId=%q, want %q", entry.TokenId, fixtureBSV21TVZNTokenId)
	}
}

// TestOrdLockLookup_FilterByTickCaseInsensitive verifies tick filtering treats
// case as canonical-uppercase per N3.
func TestOrdLockLookup_FilterByTickCaseInsensitive(t *testing.T) {
	engine := newTestEngine(t)
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "MNEE"},
		fillPkh(0x01), fillPkh(0x02), 100))
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "BSV"},
		fillPkh(0x03), fillPkh(0x04), 200))

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"tick":"mnee"}`), // lowercase query
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(answer.Outputs))
	}
}

// TestOrdLockLookup_FilterByCancelAddress decodes the supplied base58 address
// and matches it against entries' cancelPkhHex.
func TestOrdLockLookup_FilterByCancelAddress(t *testing.T) {
	engine := newTestEngine(t)
	cancelPkh := fillPkh(0xab)
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "ABCD"},
		cancelPkh, fillPkh(0xcd), 100))
	admitOrdLockToEngine(t, engine, buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "EFGH"},
		fillPkh(0xee), fillPkh(0xff), 200))

	addr, _ := script.NewAddressFromPublicKeyHash(cancelPkh, true)
	q := fmt.Sprintf(`{"cancelAddress":"%s"}`, addr.AddressString)
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(q),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(answer.Outputs))
	}
	var entry OrdLockEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)
	if entry.Tick != "ABCD" {
		t.Errorf("got tick=%q, want ABCD", entry.Tick)
	}
}

// TestOrdLockLookup_PaginationLimitsAndOffsets exercises both bounds.
func TestOrdLockLookup_PaginationLimitsAndOffsets(t *testing.T) {
	engine := newTestEngine(t)
	for i := 0; i < 5; i++ {
		scr := buildOrdLockScriptForTest(t,
			map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": fmt.Sprintf("T%03d", i)},
			fillPkh(byte(i+1)), fillPkh(byte(0xa0+i)), uint64(100+i))
		admitOrdLockToEngine(t, engine, scr)
	}

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all","limit":2,"offset":1}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 2 {
		t.Errorf("limit=2 should return 2, got %d", len(answer.Outputs))
	}

	// Offset past the end → empty.
	answer, _ = engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all","limit":10,"offset":99}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("offset past end should return 0, got %d", len(answer.Outputs))
	}
}

// TestOrdLockLookup_DefaultSortNewestFirst verifies the default sort key.
func TestOrdLockLookup_DefaultSortNewestFirst(t *testing.T) {
	engine := newTestEngine(t)
	scr1 := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "ONEE"},
		fillPkh(0x11), fillPkh(0xaa), 1)
	scr2 := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TWOO"},
		fillPkh(0x22), fillPkh(0xbb), 2)

	admitOrdLockToEngine(t, engine, scr1)
	time.Sleep(1100 * time.Millisecond) // ensure RFC3339 second-level distinction
	admitOrdLockToEngine(t, engine, scr2)

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 2 {
		t.Fatalf("expected 2, got %d", len(answer.Outputs))
	}
	var first, second OrdLockEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &first)
	_ = json.Unmarshal(answer.Outputs[1].Metadata, &second)
	if first.Tick != "TWOO" || second.Tick != "ONEE" {
		t.Errorf("expected newest-first [TWOO, ONEE], got [%s, %s]", first.Tick, second.Tick)
	}
}

// TestOrdLockLookup_SpentListingDisappears closes the loop on N1: when a
// purchase/cancel tx submitted to the overlay spends an admitted listing, the
// entry is removed from subsequent lookups.
func TestOrdLockLookup_SpentListingDisappears(t *testing.T) {
	engine := newTestEngine(t)

	// Admit one listing.
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "GONE"},
		fillPkh(0xab), fillPkh(0xcd), 100)
	listingTxid := admitOrdLockToEngine(t, engine, scr)

	// Sanity: it's there.
	answer, _ := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 1 {
		t.Fatalf("setup: expected 1 listing, got %d", len(answer.Outputs))
	}

	// Build a tx that spends the listing's vout 0 (no new listing produced).
	hash, _ := chainhash.NewHashFromHex(listingTxid)
	spend := transaction.NewTransaction()
	spend.AddInput(&transaction.TransactionInput{
		SourceTXID:       hash,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	plain := scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	spend.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: plain})
	if _, err := engine.Submit(spend.Bytes(), []string{OrdLockTopicName}); err != nil {
		t.Fatalf("spend submit: %v", err)
	}

	// Listing should now be gone.
	answer, _ = engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("after overlay-submitted spend, expected 0 listings, got %d", len(answer.Outputs))
	}
}
