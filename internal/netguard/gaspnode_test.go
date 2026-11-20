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

// gaspNodeReplyWithProof is gaspNodeReply with a non-empty Proof: the shape
// RISK 4 (cold review round 4 cycle 6) named, where spv.Verify accepts a
// transaction a merkle path proves mined without ever running its scripts,
// so gaspNodeMalformed must not check one. proof need not be a real merkle
// path: gaspNodeMalformed only ever reads whether it is empty, the same as
// doNodeRequest's own caller does before it is parsed (gasp-storage.go's
// AppendToGraph and FindNeededInputs, which run after RequestNode returns).
func gaspNodeReplyWithProof(t *testing.T, rawTx []byte, proof string) []byte {
	t.Helper()
	body, err := json.Marshal(&gasp.Node{GraphID: gaspOutpoint, RawTx: hex.EncodeToString(rawTx), OutputIndex: 0, Proof: &proof})
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
// OverlayGASPRemote.RequestNode decoded to the same gasp.Node a direct,
// unguarded client would get -- not byte for byte (the guard hands on
// decodeGASPNode's own consumed slice, never the reply's original bytes
// unchanged; see checkGASPNode's doc comment), but field for field, by
// reflect.DeepEqual on what each client actually decodes. Each case
// populates every field doNodeRequest's own gasp.Node can carry -- Proof,
// TxMetadata, OutputMetadata and Inputs, not just RawTx, GraphID and
// OutputIndex -- so a guard change that dropped or altered one of them in
// the slice it hands on would show up here (cold review round 4 cycle 6b
// nit; folds in zz_rev2_roundtrip_test.go's TestRev2_HonestFullNodeThroughGuard,
// which checked the same guarded-vs-unguarded property through the same
// code path).
func TestGuard_PassesHonestGASPNodeReply(t *testing.T) {
	txHex := hex.EncodeToString(honestTx(t))
	cases := map[string]*gasp.Node{
		"unproven, metadata and inputs": {
			GraphID:        gaspOutpoint,
			RawTx:          txHex,
			OutputIndex:    2,
			TxMetadata:     "tm <&>",
			OutputMetadata: "om",
			Inputs:         map[string]*gasp.Input{"aa": {Hash: "bb"}},
		},
		"proven, metadata": {
			GraphID:        gaspOutpoint,
			RawTx:          txHex,
			OutputIndex:    0,
			Proof:          stringPtr("fe0100000001"),
			TxMetadata:     "tm",
			OutputMetadata: "om",
		},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(node)
			if err != nil {
				t.Fatalf("marshal gasp.Node: %v", err)
			}
			url, _ := serveAnswer(t, "application/json", body, false)

			want, err := engine.NewOverlayGASPRemote(url, "tm_test", &http.Client{}, 8).
				RequestNode(context.Background(), nil, gaspOutpoint, true)
			if err != nil {
				t.Fatalf("unguarded RequestNode: %v", err)
			}
			got, err := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8).
				RequestNode(context.Background(), nil, gaspOutpoint, true)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("guarded RequestNode differs: err %v\n got  %+v\n want %+v", err, got, want)
			}
		})
	}
}

// stringPtr returns a pointer to s, for a gasp.Node literal's Proof field.
func stringPtr(s string) *string { return &s }

// TestGuard_RefusesEveryTrailingByteVariant is cold review round 4 cycle 6's
// B1 reproduction, adapted into a permanent regression: checkGASPNode used to
// decode a reply with json.Unmarshal, which fails on anything after the JSON
// object, so it handed every one of these variants on unchecked (fail open),
// while go-overlay-services' own json.Decoder.Decode reads only the first
// value and accepts every one of them, embedded malformed script included.
// Decoding the same way (decodeGASPNode) closes the gap: every variant below
// carries the B1 shape and must be refused, exactly as the plain control
// already was.
func TestGuard_RefusesEveryTrailingByteVariant(t *testing.T) {
	good := gaspNodeReply(t, malformedReparseTx(t))
	cases := map[string][]byte{
		"plain (control)":        good,
		"trailing byte":          append(append([]byte{}, good...), 'x'),
		"trailing second object": append(append([]byte{}, good...), []byte(`{}`)...),
		"trailing close bracket": append(append([]byte{}, good...), ']'),
		"trailing NUL":           append(append([]byte{}, good...), 0x00),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url, hits := serveAnswer(t, "application/json", body, false)
			_, err := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8).
				RequestNode(context.Background(), nil, gaspOutpoint, false)
			if err == nil || !strings.Contains(err.Error(), "netguard: refused a GASP node reply") ||
				!strings.Contains(err.Error(), "undecodable instruction") {
				t.Fatalf("%s: want the guard to refuse it, got: %v", name, err)
			}
			if got := hits.Load(); got != 1 {
				t.Fatalf("%s: expected one request to the peer, got %d", name, got)
			}
		})
	}
}

// TestGuard_PassesProvenGASPNodeEvenWithAMalformedScript: a node that
// carries a Proof is handed on even though its transaction's unlocking
// script ends in an undecodable instruction -- the exact shape
// TestGuard_RefusesMalformedGASPNodeReply proves refused on its own, here
// paired with a Proof (cold review round 4 cycle 6, RISK 4). spv.Verify
// never runs the scripts of a transaction a merkle path proves mined, so
// refusing this would refuse a shape go-sdk's own verification can never
// reach.
func TestGuard_PassesProvenGASPNodeEvenWithAMalformedScript(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", gaspNodeReplyWithProof(t, malformedReparseTx(t), "not a real merkle path, just non-empty"), false)

	_, err := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	if err != nil {
		t.Fatalf("a proven node must be handed on even with a malformed script, got: %v", err)
	}
}
