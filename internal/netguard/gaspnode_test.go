package netguard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/scriptcost"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// gaspOutpoint is an arbitrary outpoint for a node request: the fake server
// below, like serveAnswer's other callers, ignores the request and serves
// canned bytes regardless of what it asks for.
var gaspOutpoint = &transaction.Outpoint{Txid: chainhash.Hash{0x01}, Index: 0}

// malformedReparseTx returns the raw bytes of a minimal version-2
// transaction with one input whose unlocking script ends in an undecodable
// instruction: the B1 shape (cold review round 4) checkGASPNode must refuse.
// It needs no funded parent, BEEF or SPV proof -- EndsMalformed
// (internal/scriptcost) is a syntactic read of the unlocking script's own
// bytes alone, and checkGASPNode never calls spv.Verify or the interpreter.
func malformedReparseTx(t *testing.T) []byte {
	t.Helper()
	us := script.Script{script.OpPUSHDATA1, 0x05} // claims 5 bytes, none follow
	if !scriptcost.EndsMalformed(us) {
		t.Fatal("fixture bug: us is not actually malformed")
	}
	tx := transaction.NewTransaction()
	tx.Version = 2
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &us,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	lock := script.Script{script.OpTRUE}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	return tx.Bytes()
}

// honestTx returns the raw bytes of a minimal, honestly-shaped transaction:
// one input with an empty unlocking script, which EndsMalformed never flags
// (an empty script has no instruction to be malformed, honest or not).
func honestTx(t *testing.T) []byte {
	t.Helper()
	empty := script.Script{}
	tx := transaction.NewTransaction()
	tx.Version = 2
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &empty,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	lock := script.Script{script.OpTRUE}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	return tx.Bytes()
}

// gaspNodeReply marshals rawTx into the JSON shape doNodeRequest's own
// json.Decoder expects from a /requestForeignGASPNode reply.
func gaspNodeReply(t *testing.T, rawTx []byte) []byte {
	t.Helper()
	body, err := json.Marshal(&gasp.Node{GraphID: gaspOutpoint, RawTx: hex.EncodeToString(rawTx), OutputIndex: 0})
	if err != nil {
		t.Fatalf("marshal gasp.Node: %v", err)
	}
	return body
}

// TestGuard_RefusesMalformedGASPNodeReply: a hostile SHIP-advertised peer's
// /requestForeignGASPNode reply carrying the B1 shape is refused through
// http.DefaultClient before go-overlay-services' own
// OverlayGASPRemote.RequestNode (gasp-remote.go) ever decodes it -- an
// ordinary failed request to that one peer, the same as a network error
// would produce.
func TestGuard_RefusesMalformedGASPNodeReply(t *testing.T) {
	url, hits := serveAnswer(t, "application/json", gaspNodeReply(t, malformedReparseTx(t)), false)
	remote := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8)

	_, err := remote.RequestNode(context.Background(), nil, gaspOutpoint, false)
	if err == nil || !strings.Contains(err.Error(), "netguard: refused a GASP node reply") ||
		!strings.Contains(err.Error(), "undecodable instruction") {
		t.Fatalf("expected the guard to refuse the reply, got: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected one request to the peer, got %d", got)
	}
}

// TestGuard_PassesHonestGASPNodeReply: an honest reply reaches
// OverlayGASPRemote.RequestNode decoded exactly as it would through an
// unguarded client, byte for byte.
func TestGuard_PassesHonestGASPNodeReply(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", gaspNodeReply(t, honestTx(t)), false)

	want, err := engine.NewOverlayGASPRemote(url, "tm_test", &http.Client{}, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	if err != nil {
		t.Fatalf("unguarded RequestNode: %v", err)
	}
	got, err := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("guarded RequestNode differs: err %v\n got  %+v\n want %+v", err, got, want)
	}
}
