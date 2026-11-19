package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestBroadcast_StoresTheBEEFValidated: an Atomic BEEF holding a transaction
// outside its subject's graph, as ts-sdk 2.1.0's Beef.getBeefForAtomic leaves
// an older unrelated one, which go-sdk's own Atomic parser refuses, is
// accepted; the copy the proof store keeps, and serves, is the BEEF
// validated, without it.
func TestBroadcast_StoresTheBEEFValidated(t *testing.T) {
	srv := testServerGullible(t)
	yes := true
	parent := beefnormtest.Parent(30, 1, 1000)
	parent.MerklePath = transaction.NewMerklePath(100, [][]*transaction.PathElement{{{Offset: 0, Hash: parent.TxID(), Txid: &yes}}})
	unrelated := beefnormtest.Parent(31, 1, 1000)
	subject := beefnormtest.Spend(parent)
	body := beefnormtest.Atomic(subject, beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{parent.MerklePath}, unrelated, parent))
	if _, _, err := transaction.NewBeefFromAtomicBytes(body); err == nil {
		t.Fatal("go-sdk accepts the unrelated transaction; the case is not the one ts-sdk sends")
	}

	req := httptest.NewRequest(http.MethodPost, "/broadcast", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var resp BroadcastResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || !resp.Stored {
		t.Fatalf("broadcast = %d %s (%v)", w.Code, w.Body.String(), err)
	}

	stored, err := srv.proofStore.GetBEEF(subject.TxID().String())
	if err != nil {
		t.Fatal(err)
	}
	beef, txid, err := transaction.NewBeefFromAtomicBytes(stored)
	if err != nil || !txid.IsEqual(subject.TxID()) {
		t.Fatalf("stored copy: %v, subject %v", err, txid)
	}
	if beef.FindTransactionByHash(unrelated.TxID()) != nil || beef.FindTransactionByHash(parent.TxID()) == nil {
		t.Error("the stored copy holds the unrelated transaction or lacks the parent")
	}
	if mempoolTx, ok := srv.broadcaster.Mempool().Get(subject.TxID().String()); !ok || !bytes.Equal(mempoolTx, subject.Bytes()) {
		t.Error("the subject is not in the mempool as itself")
	}
}
