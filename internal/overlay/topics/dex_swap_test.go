package topics

import (
	"encoding/json"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// buildSwapTxWithLayout builds a transaction with the requested output layout.
// outputs is a list of script builders; the function constructs the tx and
// returns its raw bytes. Callers use helpers like p2pkhScript and
// dexSwapMetadataScript to provide scripts.
func buildSwapTxWithLayout(t *testing.T, outputs ...*script.Script) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	for _, s := range outputs {
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      1,
			LockingScript: s,
		})
	}
	return tx.Bytes()
}

// p2pkhScript returns a spendable P2PKH-ish locking script (bytes don't
// need to parse as a real P2PKH; just needs to not be OP_RETURN).
func p2pkhScript(t *testing.T) *script.Script {
	t.Helper()
	s, err := script.NewFromHex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	if err != nil {
		t.Fatalf("build p2pkh script: %v", err)
	}
	return s
}

// opReturnScript returns an unspendable OP_RETURN output (not a metadata
// marker — just arbitrary data).
func opReturnScript(t *testing.T) *script.Script {
	t.Helper()
	s, err := script.NewFromHex("6a046b696c6c") // OP_RETURN "kill"
	if err != nil {
		t.Fatalf("build opreturn script: %v", err)
	}
	return s
}

// dexSwapMetadataScript builds a valid OP_FALSE OP_RETURN dex.swap.offer
// metadata output pointing at the given offerVout.
func dexSwapMetadataScript(t *testing.T, offerVout int) *script.Script {
	t.Helper()
	entry := DEXSwapEntry{
		Maker:        "02abcdef",
		Offering:     json.RawMessage(`{"kind":"bsv","sats":1000}`),
		Requesting:   json.RawMessage(`{"kind":"token","id":"MNEE","amount":50}`),
		RefundHeight: 950000,
		OfferVout:    offerVout,
	}
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}

	// OP_FALSE (0x00) OP_RETURN (0x6a) + 3 pushdata fields
	out := []byte{0x00, 0x6a}
	out = append(out, pushData([]byte(DEXSwapProtocol))...)
	out = append(out, pushData([]byte{byte(DEXSwapVersion)})...)
	out = append(out, pushData(body)...)

	s := script.Script(out)
	return &s
}

// pushData returns script bytes that push the given data. Handles lengths
// 1-75 (direct), 76-255 (OP_PUSHDATA1), 256-65535 (OP_PUSHDATA2).
func pushData(data []byte) []byte {
	n := len(data)
	switch {
	case n <= 75:
		out := []byte{byte(n)}
		return append(out, data...)
	case n <= 255:
		out := []byte{0x4c, byte(n)}
		return append(out, data...)
	default:
		out := []byte{0x4d, byte(n & 0xff), byte((n >> 8) & 0xff)}
		return append(out, data...)
	}
}

// --- Positive cases ---

// TestDEXSwapAdmit_ValidAdjacent_Admits verifies the happy path: a P2PKH
// offer at vout 0 followed by valid metadata at vout 1 → admitted, with the
// entry's metadata stored on the offer output.
func TestDEXSwapAdmit_ValidAdjacent_Admits(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	txData := buildSwapTxWithLayout(t,
		p2pkhScript(t),             // vout 0: the offer
		dexSwapMetadataScript(t, 0), // vout 1: metadata claiming offerVout=0
	)

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result == nil {
		t.Fatal("expected admittance instructions, got nil")
	}
	if len(result.OutputsToAdmit) != 1 || result.OutputsToAdmit[0] != 0 {
		t.Errorf("expected OutputsToAdmit=[0], got %v", result.OutputsToAdmit)
	}
	if result.OutputMetadata[0] == nil {
		t.Error("expected metadata stored on offer output")
	}
}

// --- Rejection paths (adversarial inputs) ---

// TestDEXSwapAdmit_RejectsNonAdjacentMetadata verifies that metadata must be
// at vout = offerVout + 1. A publisher who tries to point metadata at a
// distant output (to pollute the topic index) is rejected.
func TestDEXSwapAdmit_RejectsNonAdjacentMetadata(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	// offer at vout 0, metadata at vout 2 claiming offerVout=0 (gap = non-adjacent)
	txData := buildSwapTxWithLayout(t,
		p2pkhScript(t),              // vout 0
		p2pkhScript(t),              // vout 1 (unrelated output)
		dexSwapMetadataScript(t, 0), // vout 2 metadata — not adjacent to vout 0
	)

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("non-adjacent metadata must not admit; got OutputsToAdmit=%v", result.OutputsToAdmit)
	}
}

// TestDEXSwapAdmit_RejectsPointToMetadataItself verifies that offerVout
// cannot reference the metadata output itself (self-reference is nonsense
// and would get the OP_RETURN admitted as an "offer").
func TestDEXSwapAdmit_RejectsPointToMetadataItself(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	// metadata at vout 0 claiming offerVout=0 (points at itself)
	txData := buildSwapTxWithLayout(t,
		dexSwapMetadataScript(t, 0), // vout 0 — metadata pointing at itself
		p2pkhScript(t),              // vout 1
	)

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	// Metadata at vout 0 with offerVout=0 → offerVout != metadataVout-1 (-1 != 0),
	// so adjacency check rejects.
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("self-referencing offerVout must not admit; got %v", result.OutputsToAdmit)
	}
}

// TestDEXSwapAdmit_RejectsOfferVoutAtOPReturn verifies that the referenced
// offer output must be spendable. A metadata output pointing at another
// OP_RETURN is an attempt to pollute the topic index.
func TestDEXSwapAdmit_RejectsOfferVoutAtOPReturn(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	// OP_RETURN at vout 0, metadata at vout 1 claiming offerVout=0
	txData := buildSwapTxWithLayout(t,
		opReturnScript(t),            // vout 0 — not spendable
		dexSwapMetadataScript(t, 0), // vout 1
	)

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("offer pointing at OP_RETURN must not admit; got %v", result.OutputsToAdmit)
	}
}

// TestDEXSwapAdmit_RejectsOfferVoutOutOfRange verifies that out-of-range
// offerVout is rejected (malformed metadata).
func TestDEXSwapAdmit_RejectsOfferVoutOutOfRange(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	// Only one output; metadata references a non-existent vout.
	// Build manually since the builder has to emit metadata claiming vout=5.
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: dexSwapMetadataScript(t, 5), // offerVout=5, out of range
	})
	txData := tx.Bytes()

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("out-of-range offerVout must not admit; got %v", result.OutputsToAdmit)
	}
}

// TestDEXSwapAdmit_IgnoresNonMetadataOutputs verifies that transactions
// without any metadata output produce no admissions.
func TestDEXSwapAdmit_IgnoresNonMetadataOutputs(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	txData := buildSwapTxWithLayout(t, p2pkhScript(t), p2pkhScript(t))

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil {
		t.Errorf("no metadata output, expected nil result; got %v", result)
	}
}

// TestDEXSwapAdmit_InvalidTxReturnsError verifies parse errors propagate
// (not silently ignored).
func TestDEXSwapAdmit_InvalidTxReturnsError(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	_, err := tm.Admit([]byte{0x01, 0x02, 0x03}, nil) // garbage
	if err == nil {
		t.Fatal("expected error on invalid tx bytes")
	}
}

// --- Spent coin handling ---

// TestDEXSwapAdmit_MarksSpentWhenOffersConsumed verifies that spending a
// previously-admitted offer UTXO produces a CoinsRemoved entry.
func TestDEXSwapAdmit_MarksSpentWhenOffersConsumed(t *testing.T) {
	tm := NewDEXSwapTopicManager()
	txData := buildSwapTxWithLayout(t, p2pkhScript(t)) // no metadata, just consumption

	result, err := tm.Admit(txData, []overlay.AdmittedOutput{
		{Txid: "aabbcc", Vout: 0, Topic: DEXSwapTopicName},
	})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result when coins are consumed")
	}
	if len(result.CoinsRemoved) != 1 || result.CoinsRemoved[0] != 0 {
		t.Errorf("expected CoinsRemoved=[0], got %v", result.CoinsRemoved)
	}
}

// --- isSpendableOffer helper ---

func TestIsSpendableOffer(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
		want   bool
	}{
		{"empty", []byte{}, false},
		{"bare OP_RETURN", []byte{0x6a, 0x01, 0xff}, false},
		{"OP_FALSE OP_RETURN", []byte{0x00, 0x6a, 0x01, 0xff}, false},
		{"P2PKH-like", []byte{0x76, 0xa9}, true},
		{"arbitrary spendable", []byte{0x51}, true}, // OP_1
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isSpendableOffer(tc.script)
			if got != tc.want {
				t.Errorf("isSpendableOffer(%x) = %v, want %v", tc.script, got, tc.want)
			}
		})
	}
}
