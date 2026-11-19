package spv

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// emptyTxsBEEF is a V2 BEEF of n distinct empty transactions, ten bytes each,
// which go-sdk's parse holds hundreds of bytes for.
func emptyTxsBEEF(n int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(transaction.BEEF_V2))
	b.WriteByte(0) // no BUMPs
	b.WriteByte(0xfe)
	_ = binary.Write(&b, binary.LittleEndian, uint32(n))
	for i := 0; i < n; i++ {
		b.WriteByte(0) // raw transaction, no BUMP
		_ = binary.Write(&b, binary.LittleEndian, uint32(i+1))
		b.WriteByte(0) // no inputs
		b.WriteByte(0) // no outputs
		_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	}
	return b.Bytes()
}

// TestValidateBEEFRefusesTooComplexBeforeParsing: a BEEF over a beefscan cap
// is invalid, with beefscan's code in the message, and counted under its own
// failure reason; one at the cap reaches go-sdk's parser.
func TestValidateBEEFRefusesTooComplexBeforeParsing(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	over := emptyTxsBEEF(beefscan.Default.Txs + 1)
	res, err := v.ValidateBEEF(context.Background(), over)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Confidence != ConfidenceInvalid || !strings.HasPrefix(res.Message, beefscan.Code+": ") {
		t.Fatalf("over the cap: %+v, want invalid with %s", res, beefscan.Code)
	}
	if got := v.Stats().FailureByReason["too_complex"]; got != 1 {
		t.Fatalf("too_complex failures = %d, want 1", got)
	}
	res, err = v.ValidateBEEF(context.Background(), emptyTxsBEEF(beefscan.Default.Txs))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Message, beefscan.Code) {
		t.Fatalf("at the cap: refused by the scan: %+v", res)
	}
}

// TestValidateBEEFRecoversParserPanics: a panic in either go-sdk parser,
// which no known input causes now, makes a BEEF that passes the scan invalid
// instead of crashing the request.
func TestValidateBEEFRecoversParserPanics(t *testing.T) {
	origBeef, origTx := newBeefFromBytes, newTransactionFromBEEF
	t.Cleanup(func() { newBeefFromBytes, newTransactionFromBEEF = origBeef, origTx })
	body := buildTestBEEFWithBUMP(t)
	v := NewValidator(&gullibleTracker{})

	newBeefFromBytes = func([]byte) (*transaction.Beef, error) { panic("NewBeefFromBytes bug") }
	res, err := v.ValidateBEEF(context.Background(), body)
	if err != nil || res.Valid || res.Confidence != ConfidenceInvalid || !strings.Contains(res.Message, "BEEF parse panicked: NewBeefFromBytes bug") {
		t.Fatalf("NewBeefFromBytes panicking: %+v, %v", res, err)
	}
	newBeefFromBytes = origBeef
	newTransactionFromBEEF = func([]byte) (*transaction.Transaction, error) { panic("NewTransactionFromBEEF bug") }
	res, err = v.ValidateBEEF(context.Background(), body)
	if err != nil || res.Valid || res.Confidence != ConfidenceInvalid || !strings.Contains(res.Message, "transaction parse panicked: NewTransactionFromBEEF bug") {
		t.Fatalf("NewTransactionFromBEEF panicking: %+v, %v", res, err)
	}
}
