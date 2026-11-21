package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

type arcPaymentOutcome string

const (
	arcPaymentAccepted  arcPaymentOutcome = "accepted"
	arcPaymentRefused   arcPaymentOutcome = "refused"
	arcPaymentAmbiguous arcPaymentOutcome = "ambiguous"
)

func directARCOutcome(err error) arcPaymentOutcome {
	if err == nil {
		return arcPaymentAccepted
	}
	var refusal *paymentRefusal
	if errors.As(err, &refusal) && refusal.code == codePaymentNotAccepted {
		return arcPaymentRefused
	}
	if errors.As(err, &refusal) && refusal.code == codePaymentSubmitUncertain {
		return arcPaymentAmbiguous
	}
	return "unclassified"
}

// These are every row in ARC's metamorph status table
// (arc/README.md:195-210). BRC-121 treats only REJECTED as an outright
// refusal; statuses which can still move forward are ambiguous.
func TestPaymentPropertyEveryARCStatusIsClassifiedConsistently(t *testing.T) {
	rows := []struct {
		status string
		want   arcPaymentOutcome
	}{
		{"UNKNOWN", arcPaymentAmbiguous},
		{"QUEUED", arcPaymentAmbiguous},
		{"RECEIVED", arcPaymentAmbiguous},
		{"STORED", arcPaymentAmbiguous},
		{"ANNOUNCED_TO_NETWORK", arcPaymentAmbiguous},
		{"REQUESTED_BY_NETWORK", arcPaymentAmbiguous},
		{"SENT_TO_NETWORK", arcPaymentAmbiguous},
		{"ACCEPTED_BY_NETWORK", arcPaymentAmbiguous},
		{"SEEN_IN_ORPHAN_MEMPOOL", arcPaymentAmbiguous},
		{"SEEN_ON_NETWORK", arcPaymentAccepted},
		{"DOUBLE_SPEND_ATTEMPTED", arcPaymentAmbiguous},
		{"MINED_IN_STALE_BLOCK", arcPaymentAmbiguous},
		{"REJECTED", arcPaymentRefused},
		{"MINED", arcPaymentAccepted},
	}
	txid := chainhash.DoubleHashH([]byte("submitted payment"))
	for _, row := range rows {
		t.Run(row.status, func(t *testing.T) {
			resp := &txrelay.ARCResponse{TxID: txid.String(), Status: row.status}
			err := checkARCAcceptance(resp, &txid)
			got := directARCOutcome(err)
			if got != row.want {
				t.Fatalf("direct classification %q, want %q", got, row.want)
			}
			brc121 := arcPaymentAmbiguous
			if arcAccepted(row.status) {
				brc121 = arcPaymentAccepted
			} else if arcRefusedOutright(resp, err) {
				brc121 = arcPaymentRefused
			}
			if got != brc121 {
				t.Fatalf("direct classification %q differs from BRC-121 %q", got, brc121)
			}
		})
	}
}

// ARC's documented 46x answers use the same final/ambiguous boundary on the
// direct and BRC-121 paths (arc/pkg/api/status.go:18-31).
func TestPaymentPropertyARCHTTPAnswersAreClassifiedConsistently(t *testing.T) {
	for _, code := range []int{460, 461, 462, 463, 464, 465, 466, 468, 469, 471, 472, 473, 474, 475} {
		err := &txrelay.ARCHTTPError{StatusCode: code, Body: "ARC refusal"}
		directAmbiguous := paymentSubmitIsAmbiguous(err)
		brc121Refused := arcRefusedOutright(nil, err)
		if directAmbiguous == brc121Refused {
			t.Fatalf("ARC HTTP %d: direct ambiguous=%v, BRC-121 refused=%v", code, directAmbiguous, brc121Refused)
		}
	}
}

// ARC's MINED transition is emitted for the transaction hash
// (processor.go:320-333). The node additionally binds the answer to this
// submission and verifies its BRC-74 path against its own header.
func TestPaymentPropertyMinedAnswerIsBoundToLocalHeaders(t *testing.T) {
	txid := chainhash.DoubleHashH([]byte("mined payment"))
	other := chainhash.DoubleHashH([]byte("other payment"))
	const height = uint32(800_000)
	isTxid := true
	path := transaction.NewMerklePath(height, [][]*transaction.PathElement{{{Offset: 0, Hash: &txid, Txid: &isTxid}}})
	root := p2pchainhash.Hash(txid)
	prev := p2pchainhash.Hash{}
	header := wire.NewBlockHeader(1, &prev, &root, 0x1d00ffff, 1)
	var raw bytes.Buffer
	if err := header.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	pg := &PaymentGate{headerTip: func() uint32 { return height }, headerAtHeight: func(got uint32) ([]byte, error) {
		if got != height {
			t.Fatalf("header height %d", got)
		}
		return raw.Bytes(), nil
	}}
	resp := &txrelay.ARCResponse{TxID: txid.String(), Status: "MINED", BlockHeight: height,
		BlockHash: header.BlockHash().String(), MerklePath: path.Hex()}
	if err := checkARCAcceptance(resp, &txid); err != nil {
		t.Fatal(err)
	}
	if err := pg.checkPaymentFinality(resp, &txid); err != nil {
		t.Fatalf("valid local proof: %v", err)
	}
	if err := checkARCAcceptance(resp, &other); directARCOutcome(err) != arcPaymentAmbiguous {
		t.Fatalf("answer for another txid was not ambiguous: %v", err)
	}
	bad := *resp
	bad.MerklePath = transaction.NewMerklePath(height, [][]*transaction.PathElement{{{Offset: 0, Hash: &other, Txid: &isTxid}}}).Hex()
	if err := pg.checkPaymentFinality(&bad, &txid); err == nil {
		t.Fatal("MINED path for another transaction passed the local header")
	}
}

// X-Bsv-Payment is Extended Format, which carries spent outputs but not an
// unconfirmed parent's transaction. The direct path therefore submits only
// the subject. ARC's missing-input answer is an outright, clear refusal; the
// client must arrange for its parent to be known before retrying.
func TestPaymentPropertyDirectUnknownParentIsClearlyRefused(t *testing.T) {
	var submitted []byte
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		var err error
		submitted, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 462, Body: io.NopCloser(strings.NewReader("inputs missing or spent")), Header: make(http.Header)}, nil
	})
	payee := testPayeeScript(t)
	tx := buildSignedDirectPaymentTx(t, payee, 100)
	ef, err := tx.EF()
	if err != nil {
		t.Fatal(err)
	}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{}, ARCClient: arc})
	_, err = pg.verifyDirectPayment(context.Background(), hex.EncodeToString(ef), []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}})
	if err == nil || !strings.Contains(err.Error(), "462") || !strings.Contains(err.Error(), "inputs missing or spent") || !bytes.Equal(submitted, ef) {
		t.Fatalf("unknown parent: submitted subject %v, refusal %v", bytes.Equal(submitted, ef), err)
	}

	// The one submitted EF is byte-bounded before decoding. Its subject input
	// count is independently bounded before ARC sees it.
	if len(hex.EncodeToString(ef)) > maxPaymentHeaderBytes {
		t.Fatal("fixture unexpectedly exceeds the direct header bound")
	}
	_, err = pg.verifyDirectPayment(context.Background(), strings.Repeat("0", maxPaymentHeaderBytes+1), []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}})
	if !errors.Is(err, errPaymentHeaderTooLarge) {
		t.Fatalf("oversized direct payment: %v", err)
	}

	f := newBRC121Fix(t, 100)
	h := f.payment(t, 100, brc121Pay{inputs: maxDirectPaymentInputs + 1})
	rawBEEF, decodeErr := base64.StdEncoding.DecodeString(h[headerBRC121Beef])
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	p, parseErr := transaction.NewTransactionFromBEEF(rawBEEF)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	tooMany, serializeErr := p.EFHex()
	if serializeErr != nil {
		t.Fatal(serializeErr)
	}
	script := hex.EncodeToString(*p.Outputs[0].LockingScript)
	_, err = f.pg.verifyDirectPayment(context.Background(), tooMany, []Payee{{Role: "infrastructure", LockingScriptHex: script, AmountSats: 100}})
	if !errors.Is(err, errDirectPaymentUnverifiable) || len(p.Inputs) != maxDirectPaymentInputs+1 {
		t.Fatalf("unbounded subject inputs: %d, %v", len(p.Inputs), err)
	}
}
