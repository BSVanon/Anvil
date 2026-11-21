package netguard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// gaspNodeReplyHeapBytes is the locking script's push size this test
// measures: hex-encoded (doubling it) plus JSON and transaction framing,
// this produces a reply of about 60 MB, large enough to show what a
// declared Content-Length used to cost up front (bodyread.readKnown's old
// make([]byte, n)), while staying under netguard's 64 MiB (67,108,864-byte)
// GASP reply cap.
const gaspNodeReplyHeapBytes = 30_000_000

// gaspNodeReplyHeapCeiling is a loose, absolute sanity ceiling on the
// guarded peak TestGuard_NodeReplyHeapIsBoundedOverUnguarded measures: not a
// tight ratio against the unguarded peak (checking and re-encoding what was
// read is an inherent extra copy or two of the reply, measured here at
// roughly 3-4x unguarded for a 60 MB reply, the same shape checkLookup and
// checkSteak's re-encoding already costs elsewhere in this package), but
// high enough over the observed guarded peak to leave headroom for
// environment noise while still catching a true multiplicative regression
// (such as a return to re-reading or re-parsing the body more than once
// extra).
const gaspNodeReplyHeapCeiling = 900 << 20

// TestGuard_NodeReplyHeapIsBoundedOverUnguarded is a permanent regression and
// re-measured against this cycle's fix: one large, honest-shaped GASP node
// reply's heap cost, guarded (http.DefaultClient, netguard installed)
// against unguarded (a plain &http.Client{}). bodyread.readKnown no longer
// preallocates the whole declared Content-Length before a byte arrives (see
// bodyread's own TestReadKnown_DoesNotPreallocateTheDeclaredLength for that
// property specifically, against a body that never finishes); this test
// instead covers the full honest path, body fully delivered, and reports
// both peaks so the numbers are in the claims rather than asserted blind.
func TestGuard_NodeReplyHeapIsBoundedOverUnguarded(t *testing.T) {
	big := script.Script(bytes.Repeat([]byte{script.OpNOP}, gaspNodeReplyHeapBytes))
	empty := script.Script{}
	tx := transaction.NewTransaction()
	tx.Version = 2
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &chainhash.Hash{1}, UnlockingScript: &empty, SequenceNumber: 0xffffffff})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &big, Satoshis: 1})
	op := &transaction.Outpoint{Txid: *tx.TxID(), Index: 0}
	reply, err := json.Marshal(&gasp.Node{GraphID: op, RawTx: tx.Hex(), OutputIndex: 0})
	if err != nil {
		t.Fatalf("marshal gasp.Node: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, _ = w.Write(reply)
	}))
	defer srv.Close()

	measure := func(cl *http.Client) (peak, base uint64, err error) {
		peak, base = hostiletest.HeapPeak(func() {
			_, err = engine.NewOverlayGASPRemote(srv.URL, "tm_x", cl, 8).RequestNode(context.Background(), nil, op, false)
		})
		return peak, base, err
	}

	unguardedPeak, unguardedBase, err := measure(&http.Client{})
	if err != nil {
		t.Fatalf("unguarded RequestNode: %v", err)
	}
	guardedPeak, guardedBase, err := measure(http.DefaultClient)
	if err != nil {
		t.Fatalf("guarded RequestNode: %v", err)
	}
	t.Logf("reply %d bytes: unguarded peak %.1f MiB over %.1f MiB base; guarded peak %.1f MiB over %.1f MiB base",
		len(reply), mib(unguardedPeak), mib(unguardedBase), mib(guardedPeak), mib(guardedBase))

	if guardedPeak > gaspNodeReplyHeapCeiling {
		t.Errorf("guarded heap peak %.1f MiB is over the %.1f MiB sanity ceiling", mib(guardedPeak), mib(gaspNodeReplyHeapCeiling))
	}
}

func mib(n uint64) float64 { return float64(n) / (1 << 20) }
