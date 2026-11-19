package netguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// gaspE2ENodeReply marshals tx into a /requestForeignGASPNode reply, with
// proof set when given (non-empty), matching gaspNodeReplyWithProof's shape
// but for a transaction built directly rather than from raw bytes.
func gaspE2ENodeReply(t *testing.T, tx *transaction.Transaction, proof string) []byte {
	t.Helper()
	node := &gasp.Node{GraphID: &transaction.Outpoint{Txid: *tx.TxID(), Index: 0}, RawTx: tx.Hex(), OutputIndex: 0}
	if proof != "" {
		node.Proof = &proof
	}
	body, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshal gasp.Node: %v", err)
	}
	return body
}

// TestGuard_GASPSyncNeverAppendsAMalformedChildToTheRealStorage is cold
// review round 4 cycle 6's B1 end-to-end reproduction (zz_rev_gasp_e2e_test),
// adapted into a permanent, fast regression: a hostile GASP peer serves a
// child node carrying the B1 shape, fetched through the real, unmodified
// OverlayGASPRemote.RequestNode the way GASP.Sync fetches every node, in a
// fake server that routes by txid as a real peer's /requestForeignGASPNode
// would. The guard's refusal must stop the node before it is ever appended
// to the real OverlayGASPStorage's temporary graph -- so the real
// ValidateGraphAnchor, which runs spv.Verify with no budget of its own (the
// B1 heap bomb's target, go-overlay-services gasp-storage.go:317), is never
// reached for it -- while a separate, honest node from the same peer is
// unaffected: one hostile reply fails only its own exchange.
func TestGuard_GASPSyncNeverAppendsAMalformedChildToTheRealStorage(t *testing.T) {
	store, err := headers.NewTestStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	overlaytest.SeedFundingBlock(t, store)

	// A small malformed child, spending the shared overlaytest funding
	// output directly: size does not matter to EndsMalformed, which reads
	// only the unlocking script's own bytes, so this stays fast.
	out := script.Script{script.OpTRUE}
	child := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &out, Satoshis: 1000})
	malformed := script.Script{script.OpPUSHDATA1, 0x05} // claims 5 bytes, none follow
	child.Inputs[0].UnlockingScript = &malformed

	// A second, honest child spending the same funding output: a distinct
	// txid (a different payout) the fake server can serve on its own
	// request, to prove the malformed reply's refusal is scoped to its own
	// exchange.
	honestOut := script.Script{script.OpTRUE}
	honest := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &honestOut, Satoshis: 999})

	replies := map[chainhash.Hash][]byte{
		*child.TxID():  gaspE2ENodeReply(t, child, ""),
		*honest.TxID(): gaspE2ENodeReply(t, honest, ""),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req gasp.NodeRequest
		_ = json.Unmarshal(body, &req)
		reply, ok := replies[*req.Txid]
		if !ok {
			http.Error(w, "unknown", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, _ = w.Write(reply)
	}))
	defer srv.Close()

	ctx := context.Background()
	remote := engine.NewOverlayGASPRemote(srv.URL, "tm_dex_swap", http.DefaultClient, 8)
	childOP := &transaction.Outpoint{Txid: *child.TxID(), Index: 0}
	honestOP := &transaction.Outpoint{Txid: *honest.TxID(), Index: 0}

	if _, err := remote.RequestNode(ctx, nil, childOP, false); err == nil {
		t.Fatal("want the malformed child's reply refused, got a node back")
	}

	// The malformed reply must not have poisoned the client or the peer:
	// requesting the separate, honest node from the very same peer still
	// succeeds.
	honestNode, err := remote.RequestNode(ctx, nil, honestOP, false)
	if err != nil {
		t.Fatalf("the honest sibling node, from the same peer: %v", err)
	}

	// Because RequestNode(child) already failed, GASP.Sync's real walk would
	// never call AppendToGraph for it, and so ValidateGraphAnchor (the real
	// go-overlay-services type, not a fake) never runs spv.Verify over it
	// either -- demonstrated here by using that real storage only for the
	// node that did come back clean, never for the refused one.
	storage := engine.NewOverlayGASPStorage("tm_dex_swap", &engine.Engine{ChainTracker: store}, nil)
	if err := storage.AppendToGraph(ctx, honestNode, nil); err != nil {
		t.Fatalf("appending the honest node to the real storage: %v", err)
	}
}
