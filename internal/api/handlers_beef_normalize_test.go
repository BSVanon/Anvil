package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// loneLeaf is the proof of a block that holds only txid's transaction.
func loneLeaf(tx *transaction.Transaction, height uint32) *transaction.MerklePath {
	yes := true
	return transaction.NewMerklePath(height, [][]*transaction.PathElement{{{Offset: 0, Hash: tx.TxID(), Txid: &yes}}})
}

// getBEEF serves GET /tx/{txid}/beef as binary.
func getBEEF(srv *Server, txid string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/tx/"+txid+"/beef", nil)
	req.Header.Set("Accept", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestGetBEEF_CachesTheBEEFValidated: what the proof store keeps from a
// fetched BEEF, on a cache miss and on the refresh of a cached copy whose
// subject is unproven, and what the route serves, is the BEEF validated:
// entries its verification never reads are not kept.
func TestGetBEEF_CachesTheBEEFValidated(t *testing.T) {
	grandparent := beefnormtest.Parent(40, 1, 2000)
	parent := beefnormtest.Spend(grandparent)
	parent.MerklePath = loneLeaf(parent, 100)
	subject := beefnormtest.Spend(parent)
	txid := subject.TxID().String()

	// A cache miss: the parent is proven, so its own parent is not kept.
	srv := testServerGullible(t)
	srv.proofFetcher = &staticBEEFFetcher{beef: beefnormtest.Encode(t, transaction.BEEF_V1, subject, []*transaction.MerklePath{parent.MerklePath}, grandparent, parent), source: spv.BEEFSourceWoC}
	w := getBEEF(srv, txid)
	stored, err := srv.proofStore.GetBEEF(txid)
	if w.Code != http.StatusOK || err != nil || !bytes.Equal(w.Body.Bytes(), stored) {
		t.Fatalf("cache miss: %d, stored %v, or served a copy other than the one stored", w.Code, err)
	}
	kept, err := transaction.NewBeefFromBytes(stored)
	if err != nil || kept.FindTransactionByHash(grandparent.TxID()) != nil || kept.FindTransactionByHash(parent.TxID()) == nil {
		t.Errorf("cache miss: the copy stored (%v) holds the proven parent's parent, or lacks the parent", err)
	}

	// A refresh: the fetched copy proves the subject, so nothing before it
	// is kept.
	srv = testServerGullible(t)
	if _, err := srv.proofStore.StoreBEEF(beefnormtest.Encode(t, transaction.BEEF_V1, subject, []*transaction.MerklePath{parent.MerklePath}, parent)); err != nil {
		t.Fatal(err)
	}
	proven := beefnormtest.Spend(parent)
	proven.MerklePath = loneLeaf(proven, 101)
	srv.proofFetcher = &staticBEEFFetcher{beef: beefnormtest.Encode(t, transaction.BEEF_V1, proven, []*transaction.MerklePath{proven.MerklePath, parent.MerklePath}, parent), source: spv.BEEFSourceWoC}
	w = getBEEF(srv, txid)
	stored, err = srv.proofStore.GetBEEF(txid)
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "true" || err != nil || !bytes.Equal(w.Body.Bytes(), stored) {
		t.Fatalf("refresh: %d, proven %q, stored %v, or served a copy other than the one stored", w.Code, w.Header().Get("X-BEEF-Subject-Proven"), err)
	}
	kept, err = transaction.NewBeefFromBytes(stored)
	if err != nil || len(kept.Transactions) != 1 || len(kept.BUMPs) != 1 {
		t.Errorf("refresh: the copy stored (%v) holds more than the proven subject", err)
	}
}
