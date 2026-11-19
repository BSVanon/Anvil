package peerhygiene

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// largeOutputTx returns a mined-ancestry transaction with one OP_RETURN output
// carrying size bytes, so its BEEF is a little over size bytes long.
func largeOutputTx(t *testing.T, size int) *transaction.Transaction {
	t.Helper()
	s := &script.Script{}
	if err := s.AppendOpcodes(script.OpFALSE, script.OpRETURN); err != nil {
		t.Fatalf("AppendOpcodes: %v", err)
	}
	if err := s.AppendPushData(bytes.Repeat([]byte{0xAB}, size)); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
	return overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: s, Satoshis: 0})
}

// jsonAnswer marshals an output-list answer whose outputs carry the given
// BEEFs and output indexes.
func jsonAnswer(t *testing.T, outputs ...*lookup.OutputListItem) []byte {
	t.Helper()
	body, err := json.Marshal(&lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outputs})
	if err != nil {
		t.Fatalf("marshal answer: %v", err)
	}
	return body
}

func txBEEF(t *testing.T, tx *transaction.Transaction) []byte {
	t.Helper()
	b, err := tx.BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	return b
}

// TestBoundedFacilitator_RepeatedOutpointsCountAgainstBudget: eight outpoints
// naming one transaction with a 64 KiB output. Upstream re-serializes that
// transaction for every outpoint, so the answer expands to eight times its
// size, past the 4x budget, even though only one serialization is distinct.
// A reply naming the transaction once stays within it.
func TestBoundedFacilitator_RepeatedOutpointsCountAgainstBudget(t *testing.T) {
	tx := largeOutputTx(t, 64<<10)
	beef := txBEEF(t, tx)
	repeated := make([]binaryEntry, 8)
	for i := range repeated {
		repeated[i] = binaryEntry{tx: tx}
	}
	body := encodeBinaryAnswer(t, beef, repeated...)
	p := newStubPeer(t, 200, octetStream, body, false)
	_, err := lookupVia(t, &BoundedFacilitator{MaxBytes: int64(len(body))}, p.url)
	want := "binary lookup: re-serialized BEEF exceeds capacity of " + strconv.Itoa(4*len(body)) + " bytes"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q, got: %v", want, err)
	}

	once := encodeBinaryAnswer(t, beef, binaryEntry{tx: tx})
	p = newStubPeer(t, 200, octetStream, once, false)
	if _, err := lookupVia(t, &BoundedFacilitator{MaxBytes: int64(len(once))}, p.url); err != nil {
		t.Fatalf("one outpoint must fit the budget, got: %v", err)
	}
}

// TestValidateLookupAnswer_AcceptsHonestAnswers: well-formed binary, JSON
// output-list and freeform answers pass.
func TestValidateLookupAnswer_AcceptsHonestAnswers(t *testing.T) {
	txs := chainTxs(t, 2)
	binary := encodeBinaryAnswer(t, sharedBEEF(t, txs[1]),
		binaryEntry{tx: txs[0]}, binaryEntry{tx: txs[1], context: []byte("ctx")}, binaryEntry{tx: txs[0]})
	list := jsonAnswer(t, &lookup.OutputListItem{Beef: txBEEF(t, txs[1]), OutputIndex: 0})
	for name, tc := range map[string]struct {
		contentType string
		body        []byte
	}{
		"binary":   {octetStream, binary},
		"json":     {"application/json", list},
		"freeform": {"application/json", []byte(`{"type":"freeform","result":{"hosts":["a"]}}`)},
	} {
		if err := ValidateLookupAnswer(tc.contentType, tc.body); err != nil {
			t.Errorf("%s: an honest answer must pass, got: %v", name, err)
		}
	}
}

// TestValidateLookupAnswer_RejectsOutputIndexPastOutputs: go-sdk's topic
// Broadcaster indexes tx.Outputs[OutputIndex] with no bounds check, so an
// output naming index 5 of a one-output transaction would panic it. JSON and
// binary answers are both refused.
func TestValidateLookupAnswer_RejectsOutputIndexPastOutputs(t *testing.T) {
	tx := chainTxs(t, 1)[0]
	const want = "lookup: output 0 of the answer: output index 5 is past the transaction's 1 outputs"
	list := jsonAnswer(t, &lookup.OutputListItem{Beef: txBEEF(t, tx), OutputIndex: 5})
	if err := ValidateLookupAnswer("application/json", list); err == nil || err.Error() != want {
		t.Fatalf("JSON: expected %q, got: %v", want, err)
	}
	binary := encodeBinaryAnswer(t, sharedBEEF(t, tx), binaryEntry{tx: tx, index: 5})
	if err := ValidateLookupAnswer(octetStream, binary); err == nil || err.Error() != want {
		t.Fatalf("binary: expected %q, got: %v", want, err)
	}
}

// TestValidateLookupAnswer_RejectsOutputWithoutTransaction: a V1 BEEF with no
// transactions parses to a nil transaction, which the Broadcaster would
// dereference.
func TestValidateLookupAnswer_RejectsOutputWithoutTransaction(t *testing.T) {
	emptyV1 := []byte{0x01, 0x00, 0xBE, 0xEF, 0x00, 0x00} // no BUMPs, no transactions
	err := ValidateLookupAnswer("application/json", jsonAnswer(t, &lookup.OutputListItem{Beef: emptyV1}))
	if err == nil || !strings.Contains(err.Error(), "its BEEF holds no transaction") {
		t.Fatalf("expected a no-transaction error, got: %v", err)
	}
}

// TestValidateLookupAnswer_ToleratesUnparseableOutput: upstream logs and skips
// an output whose BEEF fails to parse, so one bad output must not cost the
// peer its whole answer.
func TestValidateLookupAnswer_ToleratesUnparseableOutput(t *testing.T) {
	tx := chainTxs(t, 1)[0]
	body := jsonAnswer(t,
		&lookup.OutputListItem{Beef: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}},
		&lookup.OutputListItem{Beef: txBEEF(t, tx)})
	if err := ValidateLookupAnswer("application/json", body); err != nil {
		t.Fatalf("an unparseable output must be tolerated, got: %v", err)
	}
}

// TestValidateLookupAnswer_RejectsWhatTheFacilitatorRejects: the reply-level
// checks behind BoundedFacilitator apply to ValidateLookupAnswer too.
func TestValidateLookupAnswer_RejectsWhatTheFacilitatorRejects(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
		body              []byte
		want              string
	}{
		{"outpoint count", octetStream, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, "outpoint count 4294967296 exceeds capacity"},
		{"context length", octetStream, hugeContextLenBody(), "context[0] length 9223372036854775807 exceeds capacity"},
		{"null output", "application/json", []byte(`{"type":"output-list","outputs":[null]}`), "lookup: output 0 of the answer is null"},
		{"over the cap", "application/json", freeformOfSize(int(MaxLookupResponseBytes) + 1), "body is over 33554432 bytes"},
	} {
		if err := ValidateLookupAnswer(tc.contentType, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: expected an error containing %q, got: %v", tc.name, tc.want, err)
		}
	}
}

// TestValidateLookupAnswer_ParsePanicBecomesError: if either go-sdk parser the
// lookup stack runs on an output ever panics, validation must report it as an
// error instead of passing the reply on to where the panic would be fatal.
func TestValidateLookupAnswer_ParsePanicBecomesError(t *testing.T) {
	body := jsonAnswer(t, &lookup.OutputListItem{Beef: txBEEF(t, chainTxs(t, 1)[0])})
	origParse, origNew := parseBeef, newTransactionFromBEEF
	t.Cleanup(func() { parseBeef, newTransactionFromBEEF = origParse, origNew })

	parseBeef = func([]byte) (*transaction.Beef, *transaction.Transaction, *chainhash.Hash, error) {
		panic("ParseBeef bug")
	}
	if err := ValidateLookupAnswer("application/json", body); err == nil || !strings.Contains(err.Error(), "parsing its BEEF panicked: ParseBeef bug") {
		t.Fatalf("expected the ParseBeef panic as an error, got: %v", err)
	}
	parseBeef = origParse
	newTransactionFromBEEF = func([]byte) (*transaction.Transaction, error) { panic("NewTransactionFromBEEF bug") }
	if err := ValidateLookupAnswer("application/json", body); err == nil || !strings.Contains(err.Error(), "parsing its BEEF panicked: NewTransactionFromBEEF bug") {
		t.Fatalf("expected the NewTransactionFromBEEF panic as an error, got: %v", err)
	}
}
