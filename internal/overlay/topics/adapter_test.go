package topics

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	anvilov "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// --- mock Anvil topic manager (table-driven behaviour) ----------------------

type mockAnvilTopic struct {
	docs string
	meta map[string]interface{}
	// admit is consulted on every call; the test installs whatever
	// behaviour it needs to assert.
	admit func(txData []byte, previousUTXOs []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error)
}

func (m *mockAnvilTopic) Admit(txData []byte, previousUTXOs []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
	if m.admit == nil {
		return nil, nil
	}
	return m.admit(txData, previousUTXOs)
}
func (m *mockAnvilTopic) GetDocumentation() string             { return m.docs }
func (m *mockAnvilTopic) GetMetadata() map[string]interface{} { return m.meta }

// --- helpers ----------------------------------------------------------------

// buildTxWithOpReturn produces a real tx with a single OP_FALSE OP_RETURN
// output carrying the provided payload, plus the BEEF that wraps it. Real
// signatures are not required because the adapter doesn't validate.
func buildTxWithOpReturn(t *testing.T, payload []byte) (*transaction.Transaction, *transaction.Beef) {
	t.Helper()
	tx := transaction.NewTransaction()
	// 0x00 (OP_FALSE) + 0x6a (OP_RETURN) + push payload
	sb := []byte{0x00, 0x6a, byte(len(payload))}
	sb = append(sb, payload...)
	s := script.Script(sb)
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: &s,
		Satoshis:      0,
	})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	return tx, beef
}

func makeHash(seed byte) *chainhash.Hash {
	var h chainhash.Hash
	for i := range h {
		h[i] = seed
	}
	return &h
}

// --- tests ------------------------------------------------------------------

func TestAdapter_NilArgs(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("hello"))
	txid := tx.TxID()

	if _, err := a.IdentifyAdmissibleOutputs(context.Background(), nil, txid, nil); err == nil {
		t.Fatalf("expected error for nil beef")
	}
	if _, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, nil, nil); err == nil {
		t.Fatalf("expected error for nil txid")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.IdentifyAdmissibleOutputs(ctx, beef, txid, nil); err == nil {
		t.Fatalf("expected ctx error for cancelled ctx")
	}
}

func TestAdapter_TxNotInBeef(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{}, &overlay.MetaData{Name: "tm_test"})
	_, beef := buildTxWithOpReturn(t, []byte("hello"))

	// Use a deliberately wrong txid that the BEEF doesn't contain.
	stranger := makeHash(0xAB)
	_, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, stranger, nil)
	if err == nil {
		t.Fatalf("expected error for tx not in beef")
	}
	if !errors.Is(err, ErrTxNotInBeef) {
		t.Fatalf("expected errors.Is(err, ErrTxNotInBeef), got: %v", err)
	}
	// Cosmetic: error message should still include adapter name + txid for
	// log readability.
	if !strings.Contains(err.Error(), "tm_test") {
		t.Fatalf("expected adapter name in error, got: %v", err)
	}
}

func TestAdapter_NilInnerReturn(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, _ []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			return nil, nil
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("hi"))
	got, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.OutputsToAdmit != nil || got.CoinsRemoved != nil || got.CoinsToRetain != nil {
		t.Fatalf("expected empty AdmittanceInstructions, got %+v", got)
	}
}

func TestAdapter_OutputsToAdmitConversion(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, _ []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			return &anvilov.AdmittanceInstructions{
				OutputsToAdmit: []int{0, 5, -1, 99}, // valid + out-of-range + negative
			}, nil
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("x"))
	got, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// tx has exactly 1 output; only index 0 is valid.
	if len(got.OutputsToAdmit) != 1 || got.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected [0], got %v", got.OutputsToAdmit)
	}
}

func TestAdapter_PositionToVinRemap(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, _ []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			// Anvil's slice-relative convention: position 0 + position 2.
			return &anvilov.AdmittanceInstructions{
				CoinsRemoved:  []int{0, 2},
				CoinsToRetain: []int{1},
			}, nil
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("x"))
	// Canonical previousCoins are real input indices: vin 3, vin 7, vin 11.
	previousCoins := []uint32{3, 7, 11}

	got, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), previousCoins)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.CoinsRemoved) != 2 || got.CoinsRemoved[0] != 3 || got.CoinsRemoved[1] != 11 {
		t.Fatalf("CoinsRemoved expected [3 11], got %v", got.CoinsRemoved)
	}
	if len(got.CoinsToRetain) != 1 || got.CoinsToRetain[0] != 7 {
		t.Fatalf("CoinsToRetain expected [7], got %v", got.CoinsToRetain)
	}
}

func TestAdapter_PositionOutOfRangeDropped(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, _ []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			return &anvilov.AdmittanceInstructions{
				CoinsRemoved: []int{0, 99, -1, 1},
			}, nil
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("x"))
	got, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), []uint32{2, 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.CoinsRemoved) != 2 || got.CoinsRemoved[0] != 2 || got.CoinsRemoved[1] != 5 {
		t.Fatalf("expected [2 5], got %v", got.CoinsRemoved)
	}
}

func TestAdapter_InnerError(t *testing.T) {
	innerErr := errors.New("topic-specific failure")
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, _ []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			return nil, innerErr
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("x"))
	_, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), nil)
	if err == nil || !errors.Is(err, innerErr) {
		t.Fatalf("expected wrapped inner error, got %v", err)
	}
	if !strings.Contains(err.Error(), "tm_test") {
		t.Fatalf("expected adapter name in error, got: %v", err)
	}
}

func TestAdapter_InputsPassedAsSlice(t *testing.T) {
	gotLen := -1
	a := NewAdapter("tm_test", &mockAnvilTopic{
		admit: func(_ []byte, previousUTXOs []anvilov.AdmittedOutput) (*anvilov.AdmittanceInstructions, error) {
			gotLen = len(previousUTXOs)
			return nil, nil
		},
	}, &overlay.MetaData{Name: "tm_test"})

	tx, beef := buildTxWithOpReturn(t, []byte("x"))
	if _, err := a.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), []uint32{0, 1, 2, 3}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLen != 4 {
		t.Fatalf("expected previousUTXOs length 4, got %d", gotLen)
	}
}

func TestAdapter_DocumentationAndMetaData(t *testing.T) {
	meta := &overlay.MetaData{Name: "tm_test", Description: "test topic", Version: "9.9.9"}
	a := NewAdapter("tm_test", &mockAnvilTopic{docs: "the docs"}, meta)

	if got := a.GetDocumentation(); got != "the docs" {
		t.Fatalf("docs mismatch: %q", got)
	}
	if got := a.GetMetaData(); got != meta {
		t.Fatalf("meta pointer mismatch")
	}
}

func TestAdapter_IdentifyNeededInputs(t *testing.T) {
	a := NewAdapter("tm_test", &mockAnvilTopic{}, &overlay.MetaData{Name: "tm_test"})
	ops, err := a.IdentifyNeededInputs(context.Background(), nil, nil)
	if err != nil || ops != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", ops, err)
	}
}

// --- end-to-end: real UHRP advertisement through the adapter ---------------

func TestUHRPCanonical_AdmitsRealUHRPOutput(t *testing.T) {
	// Build a UHRP advertisement payload exactly as BuildUHRPScript would.
	hash, _ := hex.DecodeString(strings.Repeat("ab", 32))
	scriptBytes := []byte{0x00, 0x6a, 0x04, 'U', 'H', 'R', 'P', byte(len(hash))}
	scriptBytes = append(scriptBytes, hash...)

	tx := transaction.NewTransaction()
	s := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &s, Satoshis: 0})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("beef: %v", err)
	}

	tm := UHRPCanonical()
	got, err := tm.IdentifyAdmissibleOutputs(context.Background(), beef, tx.TxID(), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if len(got.OutputsToAdmit) != 1 || got.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted, got %v", got.OutputsToAdmit)
	}
}

func TestAllCanonicalConstructors_ImplementInterface(t *testing.T) {
	cases := []struct {
		name string
		make func() engine.TopicManager
		want string
	}{
		{"UHRP", UHRPCanonical, UHRPTopicName},
		{"DEXSwap", DEXSwapCanonical, DEXSwapTopicName},
		{"OrdLock", OrdLockCanonical, OrdLockTopicName},
		{"OrdLockBuy", OrdLockBuyCanonical, OrdLockBuyTopicName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tm := c.make()
			if tm == nil {
				t.Fatalf("%s constructor returned nil", c.name)
			}
			md := tm.GetMetaData()
			if md == nil || md.Name != c.want {
				t.Fatalf("%s metadata mismatch: got %+v want Name=%s", c.name, md, c.want)
			}
			if tm.GetDocumentation() == "" {
				t.Fatalf("%s documentation empty", c.name)
			}
			ops, err := tm.IdentifyNeededInputs(context.Background(), nil, nil)
			if err != nil || ops != nil {
				t.Fatalf("%s IdentifyNeededInputs: got (%v, %v)", c.name, ops, err)
			}
		})
	}
}
