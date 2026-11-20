package netguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// gaspProofSkipParentPush sizes the huge locking script on the large parent
// (X) in TestGuard_ProvenNodeSkipsScriptsEvenWithAWrongProof: big enough that
// parsing or running it would be unmistakable in the heap and time bounds
// below, matching the 2 MB parent the reproduction this test pins measured
// against.
const gaspProofSkipParentPush = 2_000_000

// gaspProofSkipHeapBound and gaspProofSkipTimeBound are far under what
// walking into the 2 MB parent would cost, so either bound tripping is
// unmistakable evidence that a dependency upgrade started doing so.
const (
	gaspProofSkipHeapBound = 64 << 20
	gaspProofSkipTimeBound = 2 * time.Second
)

// TestGuard_ProvenNodeSkipsScriptsEvenWithAWrongProof is cold review round 4
// cycle 6b's RISK 4 pin: go-sdk's spv.Verify accepts a transaction a merkle
// path proves mined without ever running its scripts, which is why
// gaspNodeMalformed never checks a node carrying a Proof for the B1 reparse
// shape (see its own doc comment in gaspnode.go). That is only
// refusal-cheap, though, if a WRONG proof -- one that parses as a valid
// merkle path but is not actually for this transaction -- is itself
// rejected before anything walks into the rest of the graph behind it.
//
// R spends C:0 and X:1. C carries a real, parseable merkle path, but one
// that proves a different transaction (fund) mined, not itself. C's own
// input spends X:0, whose locking script is one huge push
// (gaspProofSkipParentPush bytes) -- large enough that a go-sdk upgrade
// which started walking a wrongly-proven node's inputs before rejecting its
// proof, instead of rejecting the proof outright, would show up here as a
// heap and time cost from parsing that push, not as a passing validation.
// X:0 is never even fetched in this test (deliberately absent from the
// graph handed to ValidateGraphAnchor, as in the original reproduction):
// the wrong proof must be refused without it.
func TestGuard_ProvenNodeSkipsScriptsEvenWithAWrongProof(t *testing.T) {
	store, err := headers.NewTestStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	overlaytest.SeedFundingBlock(t, store)
	fund := overlaytest.FundingTx()

	lock := []byte{script.OpPUSHDATA4, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(lock[1:], uint32(gaspProofSkipParentPush))
	lock = append(lock, bytes.Repeat([]byte{script.OpNOP}, gaspProofSkipParentPush)...)
	ls := script.Script(lock)
	one := script.Script{script.OpTRUE}
	X := overlaytest.SpendingTx(t,
		&transaction.TransactionOutput{LockingScript: &ls, Satoshis: 50_000},
		&transaction.TransactionOutput{LockingScript: &one, Satoshis: 40_000})

	C := transaction.NewTransaction()
	C.Version = 2
	C.AddInputFromTx(X, 0, nil)
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	sig, err := priv.Sign(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	der := append(sig.Serialize(), 0x41)
	pk := priv.PubKey().Compressed()
	var unlock []byte
	unlock = append(append(unlock, byte(len(der))), der...)
	unlock = append(append(unlock, byte(len(pk))), pk...)
	// Claims a 5-byte push with nothing behind it: C's own script would
	// fail if anything ever ran it, which this test asserts never happens.
	unlock = append(unlock, script.OpCHECKSIG, script.OpDROP, script.OpPUSHDATA1, 0x05)
	us := script.Script(unlock)
	C.Inputs[0].UnlockingScript = &us
	C.AddOutput(&transaction.TransactionOutput{LockingScript: &one, Satoshis: 1000})

	R := transaction.NewTransaction()
	R.AddInputFromTx(C, 0, nil)
	R.AddInputFromTx(X, 1, nil)
	e1, e2 := script.Script{}, script.Script{}
	R.Inputs[0].UnlockingScript = &e1
	R.Inputs[1].UnlockingScript = &e2
	R.AddOutput(&transaction.TransactionOutput{LockingScript: &one, Satoshis: 500})

	rootOP := &transaction.Outpoint{Txid: *R.TxID(), Index: 0}
	wrongProof := fund.MerklePath.Hex() // real, parseable -- but proves fund, not C
	mk := func(tx *transaction.Transaction, idx uint32, proof *string) []byte {
		body, err := json.Marshal(&gasp.Node{GraphID: rootOP, RawTx: tx.Hex(), OutputIndex: idx, Proof: proof})
		if err != nil {
			t.Fatalf("marshal gasp.Node: %v", err)
		}
		return body
	}
	type key struct {
		txid string
		idx  uint32
	}
	replies := map[key][]byte{
		{R.TxID().String(), 0}:    mk(R, 0, nil),
		{C.TxID().String(), 0}:    mk(C, 0, &wrongProof),
		{X.TxID().String(), 1}:    mk(X, 1, nil),
		{fund.TxID().String(), 0}: mk(fund, 0, &wrongProof),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req gasp.NodeRequest
		_ = json.Unmarshal(body, &req)
		reply, ok := replies[key{req.Txid.String(), req.OutputIndex}]
		if !ok {
			http.Error(w, "unknown", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, _ = w.Write(reply)
	}))
	defer srv.Close()

	ctx := context.Background()
	remote := engine.NewOverlayGASPRemote(srv.URL, "tm_dex_swap", http.DefaultClient, 8)
	get := func(tx *transaction.Transaction, idx uint32) *gasp.Node {
		node, err := remote.RequestNode(ctx, rootOP, &transaction.Outpoint{Txid: *tx.TxID(), Index: idx}, true)
		if err != nil {
			t.Fatalf("guarded RequestNode %s:%d: %v", tx.TxID(), idx, err)
		}
		return node
	}
	nR, nC, nX1, nF := get(R, 0), get(C, 0), get(X, 1), get(fund, 0)

	storage := engine.NewOverlayGASPStorage("tm_dex_swap", &engine.Engine{ChainTracker: store}, nil)
	for _, s := range []struct {
		node *gasp.Node
		by   *transaction.Outpoint
	}{
		{nR, nil},
		{nC, rootOP},
		{nX1, rootOP},
		{nF, &transaction.Outpoint{Txid: *X.TxID(), Index: 1}},
	} {
		if err := storage.AppendToGraph(ctx, s.node, s.by); err != nil {
			t.Fatalf("append %s:%d: %v", s.node.GraphID.Txid.String(), s.node.GraphID.Index, err)
		}
	}

	var verr error
	start := time.Now()
	peak, base := hostiletest.HeapPeak(func() { verr = storage.ValidateGraphAnchor(ctx, rootOP) })
	took := time.Since(start)
	t.Logf("wrong-but-parseable proof on C, %d-byte parent push: ValidateGraphAnchor took %v, heap peak %.1f MiB over %.1f MiB base, err=%v",
		gaspProofSkipParentPush, took, mib(peak), mib(base), verr)

	if verr == nil {
		t.Fatal("want the wrong proof refused, got ValidateGraphAnchor accept it")
	}
	if took > gaspProofSkipTimeBound {
		t.Errorf("refused after %v, want well under %v (refused before the large parent is ever walked)", took, gaspProofSkipTimeBound)
	}
	if peak > gaspProofSkipHeapBound {
		t.Errorf("heap peak %d bytes over base, want under %d (the large parent's push must never be read)", peak, gaspProofSkipHeapBound)
	}
}
