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
	bsvCrypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- Pure-helper tests (no engine) ---

func TestMatchesOrdLockBuyQuery(t *testing.T) {
	bsv21 := OrdLockBuyEntry{
		Outpoint:     "abc123_0",
		Protocol:     "bsv-21",
		TokenId:      "abc123_0",
		CancelPkhHex: "ab" + strings.Repeat("00", 19),
	}
	bsv20 := OrdLockBuyEntry{
		Outpoint:     "def456_0",
		Protocol:     "bsv-20",
		Tick:         "MNEE",
		CancelPkhHex: "cd" + strings.Repeat("00", 19),
	}

	tests := []struct {
		name                       string
		entry                      OrdLockBuyEntry
		tokenId, tick, cancel, out string
		want                       bool
	}{
		{"all-empty matches anything", bsv21, "", "", "", "", true},
		{"tokenId match", bsv21, "abc123_0", "", "", "", true},
		{"tokenId case-insensitive match", bsv21, "ABC123_0", "", "", "", true},
		{"tokenId mismatch", bsv21, "deadbeef_0", "", "", "", false},
		{"tick match", bsv20, "", "MNEE", "", "", true},
		{"tick mismatch", bsv20, "", "BSV", "", "", false},
		{"tokenId and tick mutually exclusive — tokenId wins", bsv21, "abc123_0", "MNEE", "", "", true},
		{"cancel match (lowercase)", bsv20, "", "", "cd" + strings.Repeat("00", 19), "", true},
		{"cancel match (mixed case)", bsv20, "", "", "Cd" + strings.Repeat("00", 19), "", true},
		{"cancel mismatch", bsv20, "", "", "ee" + strings.Repeat("00", 19), "", false},
		{"outpoint match", bsv21, "", "", "", "abc123_0", true},
		{"outpoint mismatch", bsv21, "", "", "", "ffff_0", false},
		{"tokenId AND cancel both required", bsv21, "abc123_0", "", "ab" + strings.Repeat("00", 19), "", true},
		{"tokenId match but cancel mismatch fails", bsv21, "abc123_0", "", "ee" + strings.Repeat("00", 19), "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesOrdLockBuyQuery(tc.entry, tc.tokenId, strings.ToUpper(tc.tick), strings.ToLower(tc.cancel), tc.out)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeOrdLockBuyLimitOffset(t *testing.T) {
	tests := []struct{ inL, inO, wantL, wantO int }{
		{0, 0, 100, 0},
		{50, 25, 50, 25},
		{1000, 0, 500, 0}, // capped at max
		{-5, -5, 100, 0},  // negatives → defaults
		{500, 0, 500, 0},  // exact max
	}
	for _, tc := range tests {
		gotL, gotO := normalizeOrdLockBuyLimitOffset(tc.inL, tc.inO)
		if gotL != tc.wantL || gotO != tc.wantO {
			t.Errorf("normalizeOrdLockBuyLimitOffset(%d,%d) = (%d,%d), want (%d,%d)", tc.inL, tc.inO, gotL, gotO, tc.wantL, tc.wantO)
		}
	}
}

func TestOrdLockBuyLookupService_DocMetadata(t *testing.T) {
	ls := NewOrdLockBuyLookupService(nil)
	if ls.GetDocumentation() == "" {
		t.Error("expected non-empty documentation")
	}
	meta := ls.GetMetadata()
	if meta["service"] != OrdLockBuyLookupServiceName {
		t.Errorf("service=%v, want %s", meta["service"], OrdLockBuyLookupServiceName)
	}
}

func TestOrdLockBuyLookupService_InvalidQueryReturnsError(t *testing.T) {
	ls := NewOrdLockBuyLookupService(nil)
	if _, err := ls.Lookup(json.RawMessage(`{malformed`)); err == nil {
		t.Fatal("expected error on malformed query JSON")
	}
}

func TestOrdLockBuyLookupService_InvalidCancelAddressReturnsError(t *testing.T) {
	ls := NewOrdLockBuyLookupService(nil)
	_, err := ls.Lookup(json.RawMessage(`{"cancelAddress":"not-an-address"}`))
	if err == nil {
		t.Fatal("expected error on invalid cancelAddress")
	}
}

// --- Engine-backed integration test fixtures + helpers ---

// newTestBuyEngine spins up an in-memory overlay engine pre-registered with
// the OrdLockBuy topic + lookup. Each invocation gets its own LevelDB temp
// dir so tests don't share state.
func newTestBuyEngine(t *testing.T) *overlay.Engine {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-ordlock-buy-lookup-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	engine := overlay.NewEngine(db, nil)
	engine.RegisterTopic(OrdLockBuyTopicName, NewOrdLockBuyTopicManager())
	engine.RegisterLookup(OrdLockBuyLookupServiceName, NewOrdLockBuyLookupService(engine), []string{OrdLockBuyTopicName})
	return engine
}

// admitBuyVaultToEngine builds a fresh tx wrapping the supplied vault locking
// script (vault carries the buyer's BSV — typical 1500 sats) and submits it
// through the engine. Returns the txid.
func admitBuyVaultToEngine(t *testing.T, engine *overlay.Engine, vaultScriptHex string, vaultSats uint64) string {
	t.Helper()
	tx := transaction.NewTransaction()
	// Salt the input so each tx hashes differently within a test run.
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
	scr := scriptFromHex(t, vaultScriptHex)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: vaultSats, LockingScript: scr})
	if _, err := engine.Submit(tx.Bytes(), []string{OrdLockBuyTopicName}); err != nil {
		t.Fatalf("engine.Submit: %v", err)
	}
	return tx.TxID().String()
}

// buildOrdLockBuyScriptForTest splices the OrdLockBuy artifact with caller-
// supplied constants. Mirrors the canonical TypeScript builder
// (buildBuyLockingScript in Anvil-Swap/src/ordlock/runar/buy-covenant.ts);
// the byte slots vendored in ordlock_buy.go are the source of truth, so any
// future artifact-version drift surfaces as a compile or test failure here.
func buildOrdLockBuyScriptForTest(
	t *testing.T,
	expectedOutput0Hex string,
	priceSats uint64,
	cancelPkhHex string,
	buyerPubKeyHex string,
) string {
	t.Helper()

	// Encode each slot's replacement push.
	priceSatsLE := encodeUint64LE(priceSats)
	encodings := map[ordLockBuyParamName]string{
		paramPriceSatsLE:          minimalPushHex(t, priceSatsLE),
		paramP2pkhVarintPrefix:    minimalPushHex(t, mustHex(t, ordLockBuyP2pkhVarintPrefixHex)),
		paramP2pkhSuffix:          minimalPushHex(t, mustHex(t, ordLockBuyP2pkhSuffixHex)),
		paramExpectedOutput0Bytes: minimalPushHex(t, mustHex(t, expectedOutput0Hex)),
		paramBuyerPubKey:          minimalPushHex(t, mustHex(t, buyerPubKeyHex)),
		paramCancelPkh:            minimalPushHex(t, mustHex(t, cancelPkhHex)),
	}

	// Splice in DESCENDING byteOffset order so earlier offsets stay valid
	// while we mutate later positions.
	hexStr := hex.EncodeToString(olockBuyArtifactBytes)
	for i := len(ordLockBuySlots) - 1; i >= 0; i-- {
		slot := ordLockBuySlots[i]
		replacement, ok := encodings[slot.param]
		if !ok {
			t.Fatalf("unsupported param at slot %d", i)
		}
		hexOffset := slot.byteOffset * 2
		hexStr = hexStr[:hexOffset] + replacement + hexStr[hexOffset+2:]
	}
	return hexStr
}

func encodeUint64LE(n uint64) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(n & 0xff)
		n >>= 8
	}
	return out
}

func minimalPushHex(t *testing.T, data []byte) string {
	t.Helper()
	switch {
	case len(data) == 0:
		return "00"
	case len(data) <= 75:
		return fmt.Sprintf("%02x%s", len(data), hex.EncodeToString(data))
	case len(data) <= 0xff:
		return fmt.Sprintf("4c%02x%s", len(data), hex.EncodeToString(data))
	case len(data) <= 0xffff:
		return fmt.Sprintf("4d%02x%02x%s", len(data)&0xff, (len(data)>>8)&0xff, hex.EncodeToString(data))
	default:
		t.Fatalf("push too large for tests: %d bytes", len(data))
		return ""
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// buildBSV21ExpectedOutput0Hex assembles the inscription-envelope+P2PKH push
// that BSVanon's buy vault stores as the seller's expected output 0.
func buildBSV21ExpectedOutput0Hex(t *testing.T, tokenId string, amount string, buyerOrdPkhHex string) string {
	t.Helper()
	jsonStr := fmt.Sprintf(`{"p":"bsv-20","op":"transfer","amt":"%s","id":"%s"}`, amount, tokenId)
	return assembleOutput0Hex(t, []byte(jsonStr), buyerOrdPkhHex)
}

func buildBSV20ExpectedOutput0Hex(t *testing.T, tick string, amount string, buyerOrdPkhHex string) string {
	t.Helper()
	jsonStr := fmt.Sprintf(`{"p":"bsv-20","op":"transfer","amt":"%s","tick":"%s"}`, amount, strings.ToUpper(tick))
	return assembleOutput0Hex(t, []byte(jsonStr), buyerOrdPkhHex)
}

func assembleOutput0Hex(t *testing.T, jsonBytes []byte, buyerOrdPkhHex string) string {
	t.Helper()
	if len(buyerOrdPkhHex) != 40 {
		t.Fatalf("buyerOrdPkhHex must be 20-byte hex, got %d", len(buyerOrdPkhHex))
	}
	// 8-byte sats LE = 1
	const satsHex = "0100000000000000"
	// Inscription envelope: 00 (OP_0) 63 (OP_IF) 03 6f 72 64 ("ord") 51 (OP_1)
	// 12 (push 18) "application/bsv-20" 00 (OP_0) <push of jsonBytes> 68 (OP_ENDIF)
	envelope := "0063036f72645112" + hex.EncodeToString([]byte("application/bsv-20")) + "00" + minimalPushHex(t, jsonBytes) + "68"
	// P2PKH: 76 a9 14 <pkh> 88 ac
	p2pkh := "76a914" + buyerOrdPkhHex + "88ac"
	scriptHex := envelope + p2pkh
	scriptBytes := len(scriptHex) / 2
	// Varint script length
	var varint string
	switch {
	case scriptBytes < 0xfd:
		varint = fmt.Sprintf("%02x", scriptBytes)
	case scriptBytes <= 0xffff:
		varint = fmt.Sprintf("fd%02x%02x", scriptBytes&0xff, (scriptBytes>>8)&0xff)
	default:
		t.Fatalf("script too large: %d", scriptBytes)
	}
	return satsHex + varint + scriptHex
}

// canonicalBuyerPubKey is a known compressed pubkey used across fixtures —
// hash160 happens to be deterministic so we can derive cancelPkh from it
// on the fly when we want a "valid" combo.
const canonicalBuyerPubKey = "0312e3db769544cf899b8c0961594f6c474f1f4166ad0c1b47c55413e9f2321c54"

// canonicalCancelPkh is hash160(canonicalBuyerPubKey) — pre-computed once;
// the contract requires this invariant for cancel to actually unlock funds.
const canonicalCancelPkh = "7d8cf389745e933753d26b970cb29437c4605a95"

// canonicalBuyerOrdPkh is just any 20-byte hex distinct from cancelPkh —
// for filter tests we don't need the wallet to actually own it.
const canonicalBuyerOrdPkh = "8dd8631a9c2285f523da15a1b8d874a3fda00eea"

const samplePumpkinTokenId = "3c5de613b36aadad51dac34a0472a878a42c4125b448504810927a377d5162c4_0"

// --- Engine-backed lookup tests ---

// TestOrdLockBuyLookup_AllReturnsAll walks the full lifecycle.
func TestOrdLockBuyLookup_AllReturnsAll(t *testing.T) {
	engine := newTestBuyEngine(t)
	for i := 0; i < 3; i++ {
		out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, fmt.Sprintf("%d", 50+i*10), canonicalBuyerOrdPkh)
		scr := buildOrdLockBuyScriptForTest(t, out0, uint64(1000+i), canonicalCancelPkh, canonicalBuyerPubKey)
		admitBuyVaultToEngine(t, engine, scr, uint64(1500+i))
		// Differ AdmittedAt at second granularity for the sort test below.
		time.Sleep(1100 * time.Millisecond)
	}

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 3 {
		t.Errorf("expected 3 outputs, got %d", len(answer.Outputs))
	}
}

// TestOrdLockBuyLookup_FilterByTokenId admits 1 BSV-21 + 2 BSV-20 vaults and
// confirms tokenId narrows to the BSV-21.
func TestOrdLockBuyLookup_FilterByTokenId(t *testing.T) {
	engine := newTestBuyEngine(t)

	// Fixture 1: BSV-20 ABCD
	out0a := buildBSV20ExpectedOutput0Hex(t, "ABCD", "100", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0a, 1000, canonicalCancelPkh, canonicalBuyerPubKey), 1500)

	// Fixture 2: BSV-21 Pumpkin
	out0b := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0b, 2000, canonicalCancelPkh, canonicalBuyerPubKey), 2500)

	// Fixture 3: BSV-20 EFGH
	out0c := buildBSV20ExpectedOutput0Hex(t, "EFGH", "200", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0c, 3000, canonicalCancelPkh, canonicalBuyerPubKey), 3500)

	q := fmt.Sprintf(`{"tokenId":"%s"}`, samplePumpkinTokenId)
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(q),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 BSV-21 hit, got %d", len(answer.Outputs))
	}
	var entry OrdLockBuyEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)
	if entry.TokenId != samplePumpkinTokenId {
		t.Errorf("got tokenId=%q, want %q", entry.TokenId, samplePumpkinTokenId)
	}
}

// TestOrdLockBuyLookup_FilterByTickCaseInsensitive verifies tick filtering
// canonicalizes to uppercase.
func TestOrdLockBuyLookup_FilterByTickCaseInsensitive(t *testing.T) {
	engine := newTestBuyEngine(t)
	out0a := buildBSV20ExpectedOutput0Hex(t, "MNEE", "100", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0a, 1000, canonicalCancelPkh, canonicalBuyerPubKey), 1500)
	out0b := buildBSV20ExpectedOutput0Hex(t, "BSV", "200", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0b, 2000, canonicalCancelPkh, canonicalBuyerPubKey), 2500)

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"tick":"mnee"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(answer.Outputs))
	}
}

// TestOrdLockBuyLookup_FilterByCancelAddress decodes the supplied base58
// address and matches it against entries' cancelPkhHex.
func TestOrdLockBuyLookup_FilterByCancelAddress(t *testing.T) {
	engine := newTestBuyEngine(t)

	// Vault 1 — canonical buyer (BSVanon's pubkey from the live mainnet
	// vault test fixture).
	out0a := buildBSV20ExpectedOutput0Hex(t, "FILT", "100", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0a, 1000, canonicalCancelPkh, canonicalBuyerPubKey), 1500)

	// Vault 2 — second VALID buyer pair. Use Bob's mainnet pubkey from
	// LIVE_TEST_KEYS.md and derive its hash160 dynamically so the
	// hash160(buyerPubKey) == cancelPkh invariant holds. Without this,
	// the parser would reject vault 2 at admit time (Codex review
	// 0d628245 enforcement) and the filter would coincidentally still
	// pass with 1 hit — but it'd be passing for the wrong reason.
	const bobBuyerPubKey = "02c70c6ae311f8ad6f3dff21d38487e250ab3591333ecce7a5ca749d1d71024625"
	bobPubKeyBytes, _ := hex.DecodeString(bobBuyerPubKey)
	bobCancelPkh := hex.EncodeToString(bsvCrypto.Hash160(bobPubKeyBytes))
	out0b := buildBSV20ExpectedOutput0Hex(t, "OTHR", "200", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0b, 2000, bobCancelPkh, bobBuyerPubKey), 2500)

	// Sanity: both vaults admitted.
	all, _ := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(all.Outputs) != 2 {
		t.Fatalf("setup: expected 2 admitted vaults, got %d", len(all.Outputs))
	}

	// Filter: query for vault 1's cancelAddress only.
	pkh1Bytes, _ := hex.DecodeString(canonicalCancelPkh)
	addr, _ := script.NewAddressFromPublicKeyHash(pkh1Bytes, true)
	q := fmt.Sprintf(`{"cancelAddress":"%s"}`, addr.AddressString)
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(q),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(answer.Outputs))
	}
	var entry OrdLockBuyEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)
	if entry.Tick != "FILT" {
		t.Errorf("got tick=%q, want FILT", entry.Tick)
	}
}

// TestParseOrdLockBuyScript_RejectsKeyMismatch enforces the canonical-vault
// invariant Codex review 0d6282450e930dda flagged: a vault whose cancelPkh
// is NOT the hash160 of buyerPubKey is unspendable on the cancel branch
// (sig validates against buyerPubKey, but the refund output forces P2PKH
// to cancelPkh — funds permanently lost). The parser MUST refuse to admit
// such vaults so the overlay doesn't index broken state.
//
// Mirrors the TS-side check in Anvil-Swap/src/ordlock/runar/buy-covenant.ts
// §228 (Codex review 5976f981, 2026-04-26) which rejects mismatch at
// vault-creation time.
func TestParseOrdLockBuyScript_RejectsKeyMismatch(t *testing.T) {
	out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	// Deliberate mismatch: real-format buyerPubKey, but cancelPkh that is
	// NOT its hash160.
	mismatchedCancelPkh := "ff" + strings.Repeat("ee", 19)
	scriptHex := buildOrdLockBuyScriptForTest(t, out0, 1000, mismatchedCancelPkh, canonicalBuyerPubKey)
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		t.Fatalf("decode test script: %v", err)
	}
	if entry := parseOrdLockBuyScript(script); entry != nil {
		t.Errorf("parser admitted a vault with hash160(buyerPubKey) != cancelPkh — entry=%+v", entry)
	}
}

// TestOrdLockBuyTopicManager_KeyMismatchVaultRejectedByEngine confirms the
// engine path also rejects the mismatch (no admission, lookup returns 0).
func TestOrdLockBuyTopicManager_KeyMismatchVaultRejectedByEngine(t *testing.T) {
	engine := newTestBuyEngine(t)
	out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	mismatchedCancelPkh := "ff" + strings.Repeat("ee", 19)
	mismatched := buildOrdLockBuyScriptForTest(t, out0, 1000, mismatchedCancelPkh, canonicalBuyerPubKey)
	admitBuyVaultToEngine(t, engine, mismatched, 1500)

	answer, _ := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("engine admitted key-mismatched vault — expected 0 lookup hits, got %d", len(answer.Outputs))
	}
}

// TestOrdLockBuyLookup_FilterByOutpoint narrows to a single vault.
func TestOrdLockBuyLookup_FilterByOutpoint(t *testing.T) {
	engine := newTestBuyEngine(t)
	out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	scr := buildOrdLockBuyScriptForTest(t, out0, 1000, canonicalCancelPkh, canonicalBuyerPubKey)
	txid1 := admitBuyVaultToEngine(t, engine, scr, 1500)
	admitBuyVaultToEngine(t, engine, scr, 1500) // second admittance, different txid

	q := fmt.Sprintf(`{"outpoint":"%s_0"}`, txid1)
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(q),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(answer.Outputs))
	}
	var entry OrdLockBuyEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)
	expectedOutpoint := fmt.Sprintf("%s_0", txid1)
	if entry.Outpoint != expectedOutpoint {
		t.Errorf("got outpoint=%q, want %q", entry.Outpoint, expectedOutpoint)
	}
}

// TestOrdLockBuyLookup_PaginationLimitsAndOffsets exercises both bounds.
func TestOrdLockBuyLookup_PaginationLimitsAndOffsets(t *testing.T) {
	engine := newTestBuyEngine(t)
	for i := 0; i < 5; i++ {
		out0 := buildBSV20ExpectedOutput0Hex(t, fmt.Sprintf("T%03d", i), "1", canonicalBuyerOrdPkh)
		scr := buildOrdLockBuyScriptForTest(t, out0, uint64(1000+i), canonicalCancelPkh, canonicalBuyerPubKey)
		admitBuyVaultToEngine(t, engine, scr, uint64(1500+i))
	}

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all","limit":2,"offset":1}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 2 {
		t.Errorf("limit=2 should return 2, got %d", len(answer.Outputs))
	}

	// Offset past end → empty.
	answer, _ = engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all","limit":10,"offset":99}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("offset past end should return 0, got %d", len(answer.Outputs))
	}
}

// TestOrdLockBuyLookup_DefaultSortNewestFirst verifies the default sort key.
func TestOrdLockBuyLookup_DefaultSortNewestFirst(t *testing.T) {
	engine := newTestBuyEngine(t)

	out0a := buildBSV20ExpectedOutput0Hex(t, "ONEE", "1", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0a, 1000, canonicalCancelPkh, canonicalBuyerPubKey), 1500)
	time.Sleep(1100 * time.Millisecond)
	out0b := buildBSV20ExpectedOutput0Hex(t, "TWOO", "1", canonicalBuyerOrdPkh)
	admitBuyVaultToEngine(t, engine,
		buildOrdLockBuyScriptForTest(t, out0b, 2000, canonicalCancelPkh, canonicalBuyerPubKey), 2500)

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 2 {
		t.Fatalf("expected 2, got %d", len(answer.Outputs))
	}
	var first, second OrdLockBuyEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &first)
	_ = json.Unmarshal(answer.Outputs[1].Metadata, &second)
	if first.Tick != "TWOO" || second.Tick != "ONEE" {
		t.Errorf("expected newest-first [TWOO, ONEE], got [%s, %s]", first.Tick, second.Tick)
	}
}

// TestOrdLockBuyLookup_FilledVaultDisappears closes the lifecycle on
// CoinsRemoved: when a take/cancel tx submitted to the overlay spends an
// admitted buy vault, the entry is removed from subsequent lookups. This
// is the buy-side equivalent of the SELL listings spent-listing-disappears
// test, and is what the followup polish (takeBuy submit-to-overlay) will
// rely on for "filled" status detection client-side.
func TestOrdLockBuyLookup_FilledVaultDisappears(t *testing.T) {
	engine := newTestBuyEngine(t)

	out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	scr := buildOrdLockBuyScriptForTest(t, out0, 1000, canonicalCancelPkh, canonicalBuyerPubKey)
	vaultTxid := admitBuyVaultToEngine(t, engine, scr, 1500)

	answer, _ := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 1 {
		t.Fatalf("setup: expected 1 vault, got %d", len(answer.Outputs))
	}

	// Build a tx that spends the vault's vout 0 (mimics take or cancel).
	hash, _ := chainhash.NewHashFromHex(vaultTxid)
	spend := transaction.NewTransaction()
	spend.AddInput(&transaction.TransactionInput{
		SourceTXID:       hash,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	plain := scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	spend.AddOutput(&transaction.TransactionOutput{Satoshis: 1499, LockingScript: plain})
	if _, err := engine.Submit(spend.Bytes(), []string{OrdLockBuyTopicName}); err != nil {
		t.Fatalf("spend submit: %v", err)
	}

	answer, _ = engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("after overlay-submitted spend, expected 0 vaults, got %d", len(answer.Outputs))
	}
}

// TestOrdLockBuyTopicManager_AdmitsLiveVaultViaEngine validates the full
// engine-backed admit path against the canonical live mainnet vault used
// in ordlock_buy_test.go's parser tests.
func TestOrdLockBuyTopicManager_AdmitsLiveVaultViaEngine(t *testing.T) {
	engine := newTestBuyEngine(t)
	// The same script the parser test pins.
	const liveVaultHex = "76009c63755279ab547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad6908e803000000000000041976a9147e7b0288ac7e7e4cb30100000000000000aa0063036f726451126170706c69636174696f6e2f6273762d3230004c737b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223530222c226964223a22336335646536313362333661616461643531646163333461303437326138373861343263343132356234343835303438313039323761333737643531363263345f30227d6876a9148dd8631a9c2285f523da15a1b8d874a3fda00eea88ac7c7e7c7eaa7c820128947f7701207f758767519d5279ab557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad69537a210312e3db769544cf899b8c0961594f6c474f1f4166ad0c1b47c55413e9f2321c54ad7c041976a9147e147d8cf389745e933753d26b970cb29437c4605a950288ac7e7e7c7eaa7c820128947f7701207f758768"
	admitBuyVaultToEngine(t, engine, liveVaultHex, 1500)

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 admitted vault, got %d", len(answer.Outputs))
	}
	var entry OrdLockBuyEntry
	if err := json.Unmarshal(answer.Outputs[0].Metadata, &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if entry.PriceSats != 1000 || entry.TokenId != samplePumpkinTokenId {
		t.Errorf("entry mismatch: got %+v", entry)
	}
}

// TestOrdLockBuyTopicManager_RejectsNonOrdLockBuyOutputs ensures the topic
// admits ONLY OrdLockBuy-shaped outputs even when bundled with other shapes.
func TestOrdLockBuyTopicManager_RejectsNonOrdLockBuyOutputs(t *testing.T) {
	engine := newTestBuyEngine(t)
	tx := transaction.NewTransaction()
	salt := make([]byte, 32)
	hash, _ := chainhash.NewHash(salt)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       hash,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	// Plain P2PKH — should NOT match the OrdLockBuy parser.
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	if _, err := engine.Submit(tx.Bytes(), []string{OrdLockBuyTopicName}); err != nil {
		t.Fatalf("engine.Submit: %v", err)
	}
	answer, _ := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if len(answer.Outputs) != 0 {
		t.Errorf("expected 0 admitted (script wasn't OrdLockBuy), got %d", len(answer.Outputs))
	}
}

// Ensure normalizeCancelFilter — the helper shared with the SELL-side
// lookup — still rejects a testnet-version address on this mainnet-only
// surface, even when invoked through the BUY lookup. (Same rule, same
// helper; this test pins it once for the buy path so future refactors
// don't accidentally route around it.)
func TestOrdLockBuyLookup_RejectsTestnetCancelAddress(t *testing.T) {
	pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
	testnetAddr, _ := script.NewAddressFromPublicKeyHash(pkh, false) // mainnet=false
	q := fmt.Sprintf(`{"cancelAddress":"%s"}`, testnetAddr.AddressString)
	ls := NewOrdLockBuyLookupService(nil)
	_, err := ls.Lookup(json.RawMessage(q))
	if err == nil {
		t.Errorf("testnet cancelAddress %q must be rejected on mainnet-only surface", testnetAddr.AddressString)
	}
}

// Round-trip test: a realistic vault should produce an entry whose
// scriptHex re-parses cleanly via parseOrdLockBuyScript. Defends against
// future drift between the artifact splice template and the parser.
func TestOrdLockBuyTopicManager_AdmittedScriptHexRoundTrips(t *testing.T) {
	engine := newTestBuyEngine(t)
	out0 := buildBSV21ExpectedOutput0Hex(t, samplePumpkinTokenId, "50", canonicalBuyerOrdPkh)
	scr := buildOrdLockBuyScriptForTest(t, out0, 1000, canonicalCancelPkh, canonicalBuyerPubKey)
	admitBuyVaultToEngine(t, engine, scr, 1500)

	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: OrdLockBuyLookupServiceName,
		Query:   json.RawMessage(`{"list":"all"}`),
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	var entry OrdLockBuyEntry
	_ = json.Unmarshal(answer.Outputs[0].Metadata, &entry)

	// Re-parse the stored scriptHex through the same parser the topic
	// admit uses. Should produce a complete, populated entry.
	rawScript, err := hex.DecodeString(entry.ScriptHex)
	if err != nil {
		t.Fatalf("decode stored scriptHex: %v", err)
	}
	reparsed := parseOrdLockBuyScript(rawScript)
	if reparsed == nil {
		t.Fatal("parseOrdLockBuyScript rejected the round-trip scriptHex")
	}
	if reparsed.PriceSats != 1000 {
		t.Errorf("priceSats round-trip: got %d, want 1000", reparsed.PriceSats)
	}
	if reparsed.TokenId != samplePumpkinTokenId {
		t.Errorf("tokenId round-trip: got %q, want %q", reparsed.TokenId, samplePumpkinTokenId)
	}
}

// Ensure the leveldb / overlay imports compile-link even when not
// directly consumed inside individual tests above.
var _ = leveldb.OpenFile
var _ = base58.Decode
