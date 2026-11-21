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
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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
// permanent, fast regression: a hostile GASP peer serves a child node carrying
// the malformed-script shape, fetched through the real, unmodified
// OverlayGASPRemote.RequestNode the way GASP.Sync fetches every node, in a
// fake server that routes by txid as a real peer's /requestForeignGASPNode
// would. The guard's refusal must stop the node before it is ever appended
// to the real OverlayGASPStorage's temporary graph -- so the real
// ValidateGraphAnchor, which runs spv.Verify with no budget of its own (the
// target, go-overlay-services gasp-storage.go:317), is never
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

// gaspE2ELargeParentPush and the bounds below belong to
// TestGuard_GASPBypassNeverReachesVerify: a parent locking script this big,
// and a heap/time cost far under what parsing or running it would take, so
// either bound tripping is unmistakable evidence something walked into it.
const gaspE2ELargeParentPush = 2_000_000

const (
	gaspE2EHeapBound = 64 << 20
	gaspE2ETimeBound = 2 * time.Second
)

// TestGuard_GASPBypassNeverReachesVerify is a permanent regression that
// closes two gaps:
// its malformed child had no large parent, so it could not show a heap
// regression, and -- like TestGuard_GASPSyncNeverAppendsAMalformedChildToTheRealStorage,
// which this test complements rather than repeats -- a passing run never
// actually reaches AppendToGraph or ValidateGraphAnchor for a refused node,
// so neither probe's source having that call present was, on its own,
// evidence that a reopened bypass would be caught there too.
//
// This keeps the original's own shape instead: if the malformed child --
// spending a parent whose own locking script is one huge push
// (gaspE2ELargeParentPush bytes), with or without a trailing byte after the
// JSON object -- is refused by RequestNode alone, as it must be, the real
// OverlayGASPStorage is never reached at all, asserted cheaply (heap and
// time bounds, with the large parent behind it to make that bound mean
// something). Only if RequestNode ever failed to refuse it does the test go
// on to run the real AppendToGraph and ValidateGraphAnchor the original
// probe named, and fail loudly for reaching them at all, rather than on
// whatever they happen to decide.
func TestGuard_GASPBypassNeverReachesVerify(t *testing.T) {
	store, err := headers.NewTestStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	overlaytest.SeedFundingBlock(t, store)
	fund := overlaytest.FundingTx()

	lock := []byte{script.OpPUSHDATA4, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(lock[1:], uint32(gaspE2ELargeParentPush))
	lock = append(lock, bytes.Repeat([]byte{script.OpNOP}, gaspE2ELargeParentPush)...)
	ls := script.Script(lock)
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &ls, Satoshis: 50_000})
	parentOP := &transaction.Outpoint{Txid: *parent.TxID(), Index: 0}

	// The malformed child spends parent:0 and ends in an undecodable instruction.
	malformedChild := transaction.NewTransaction()
	malformedChild.Version = 2
	malformedChild.AddInputFromTx(parent, 0, nil)
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
	var badUnlock []byte
	badUnlock = append(append(badUnlock, byte(len(der))), der...)
	badUnlock = append(append(badUnlock, byte(len(pk))), pk...)
	badUnlock = append(badUnlock, script.OpCHECKSIG, script.OpDROP, script.OpPUSHDATA1, 0x05) // claims 5 bytes, none follow
	badUS := script.Script(badUnlock)
	malformedChild.Inputs[0].UnlockingScript = &badUS
	out := script.Script{script.OpTRUE}
	malformedChild.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1000})

	rootOP := &transaction.Outpoint{Txid: *malformedChild.TxID(), Index: 0}
	fundProof := fund.MerklePath.Hex()
	mk := func(tx *transaction.Transaction, proof *string) []byte {
		body, err := json.Marshal(&gasp.Node{GraphID: rootOP, RawTx: tx.Hex(), OutputIndex: 0, Proof: proof})
		if err != nil {
			t.Fatalf("marshal gasp.Node: %v", err)
		}
		return body
	}
	parentReply := mk(parent, nil)
	fundReply := mk(fund, &fundProof)
	malformedReply := mk(malformedChild, nil)
	fundOP := &transaction.Outpoint{Txid: *fund.TxID(), Index: 0}

	for _, variant := range []struct {
		name  string
		reply []byte
	}{
		{"plain", malformedReply},
		{"trailing byte", append(append([]byte{}, malformedReply...), 'x')},
	} {
		t.Run(variant.name, func(t *testing.T) {
			replies := map[chainhash.Hash][]byte{
				*parent.TxID():         parentReply,
				*fund.TxID():           fundReply,
				*malformedChild.TxID(): variant.reply,
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
				w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
				_, _ = w.Write(reply)
			}))
			defer srv.Close()
			remote := engine.NewOverlayGASPRemote(srv.URL, "tm_dex_swap", http.DefaultClient, 8)
			ctx := context.Background()

			var nodeChild *gasp.Node
			var rerr error
			start := time.Now()
			peak, heapBase := hostiletest.HeapPeak(func() {
				nodeChild, rerr = remote.RequestNode(ctx, nil, rootOP, true)
			})
			took := time.Since(start)
			t.Logf("%s: RequestNode took %v, heap peak %.1f MiB over %.1f MiB base, err=%v",
				variant.name, took, mib(peak), mib(heapBase), rerr)

			if rerr != nil {
				// The expected, fixed outcome: refused before the real
				// storage is ever reached, cheaply even with the large
				// parent behind it.
				if took > gaspE2ETimeBound {
					t.Errorf("refused after %v, want well under %v", took, gaspE2ETimeBound)
				}
				if peak > gaspE2EHeapBound {
					t.Errorf("heap peak %d bytes over base, want under %d (the large parent's push must never be read for a refused child)", peak, gaspE2EHeapBound)
				}
				return
			}

			// Not refused: the malformed-node bypass this test guards against has
			// reopened. Follow it all the way through the real storage,
			// the same as the original probe did, and fail on reaching
			// ValidateGraphAnchor at all -- not on whatever it returns.
			t.Logf("WARNING: %s was not refused -- following it into the real storage", variant.name)
			nodeParent, err := remote.RequestNode(ctx, rootOP, parentOP, true)
			if err != nil {
				t.Fatalf("the parent's RequestNode: %v", err)
			}
			nodeFund, err := remote.RequestNode(ctx, rootOP, fundOP, true)
			if err != nil {
				t.Fatalf("the funding tx's RequestNode: %v", err)
			}
			storage := engine.NewOverlayGASPStorage("tm_dex_swap", &engine.Engine{ChainTracker: store}, nil)
			for _, step := range []struct {
				node *gasp.Node
				by   *transaction.Outpoint
			}{
				{nodeChild, nil},
				{nodeParent, rootOP},
				{nodeFund, parentOP},
			} {
				if err := storage.AppendToGraph(ctx, step.node, step.by); err != nil {
					t.Fatalf("append: %v", err)
				}
			}
			verr := storage.ValidateGraphAnchor(ctx, rootOP)
			t.Fatalf("a malformed %s child reached the real ValidateGraphAnchor (err=%v) instead of being refused", variant.name, verr)
		})
	}
}
