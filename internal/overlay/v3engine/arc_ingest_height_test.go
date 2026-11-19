package v3engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestFullHeight_CompoundPathBecomesItsTxidsOwn: a single-level compound
// path, whose root go-sdk computes over the two levels its offsets need, is
// replaced by txid's own two-level path with the same root, which another
// proof of the block then combines into without the panic the compound path
// gives; a path with all its levels is kept as it is.
func TestFullHeight_CompoundPathBecomesItsTxidsOwn(t *testing.T) {
	hash := func(b byte) *chainhash.Hash {
		var h chainhash.Hash
		h[0] = b
		return &h
	}
	yes := true
	compound := transaction.NewMerklePath(100, [][]*transaction.PathElement{{
		{Offset: 0, Hash: hash(1), Txid: &yes}, {Offset: 1, Hash: hash(2)},
		{Offset: 2, Hash: hash(3)}, {Offset: 3, Hash: hash(4)},
	}})
	root, err := compound.ComputeRoot(hash(1))
	if err != nil {
		t.Fatal(err)
	}
	// Another transaction of the block, proven the ordinary way.
	other := transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{{Offset: 2, Hash: hash(3), Txid: &yes}, {Offset: 3, Hash: hash(4)}},
		{{Offset: 0, Hash: transaction.MerkleTreeParent(hash(1), hash(2))}},
	})
	if r, err := other.ComputeRoot(hash(3)); err != nil || !r.IsEqual(root) {
		t.Fatalf("the ordinary proof's root %v (%v), want %v", r, err, root)
	}
	if p, _ := combinePanics(compound.Clone(), other); p == nil {
		t.Fatal("go-sdk combined an ordinary proof into the compound path without the panic this guards against")
	}

	got, err := fullHeight(compound, hash(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Path) != 2 {
		t.Fatalf("normalized path has %d levels, want 2", len(got.Path))
	}
	if r, err := got.ComputeRoot(hash(1)); err != nil || !r.IsEqual(root) {
		t.Fatalf("normalized root %v (%v), want %v", r, err, root)
	}
	if p, err := combinePanics(got, other); p != nil || err != nil {
		t.Fatalf("combining into the normalized path: panic %v, error %v", p, err)
	}

	tall := transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{{Offset: 0, Hash: hash(1), Txid: &yes}, {Offset: 1, Hash: hash(2)}},
		{{Offset: 1, Hash: transaction.MerkleTreeParent(hash(3), hash(4))}},
	})
	if kept, err := fullHeight(tall, hash(1)); err != nil || kept != tall {
		t.Fatalf("a path with every level was replaced (%v)", err)
	}
	if _, err := fullHeight(compound, hash(7)); err == nil {
		t.Fatal("a compound path that does not hold the txid was accepted")
	}
}

// TestArcIngestHandler_NormalizesProofsFirst: /arc-ingest runs fullHeight
// before the engine sees a proof, so a single-level compound path that does
// not hold the txid is refused as an invalid merkle path rather than handed
// to the engine.
func TestArcIngestHandler_NormalizesProofsFirst(t *testing.T) {
	var leaves []*transaction.PathElement
	for i := byte(0); i < 4; i++ {
		var h chainhash.Hash
		h[0] = i + 1
		leaves = append(leaves, &transaction.PathElement{Offset: uint64(i), Hash: &h})
	}
	var txid chainhash.Hash
	txid[0] = 7
	body, _ := json.Marshal(arcIngestRequest{
		Txid:        txid.String(),
		MerklePath:  transaction.NewMerklePath(100, [][]*transaction.PathElement{leaves}).Hex(),
		BlockHeight: 100,
	})
	resp, err := http.Post(newTestServer(t)+"/arc-ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "invalid merklePath: ")
}

// combinePanics combines other into mp, reporting what it panicked with, or
// the error it returned.
func combinePanics(mp, other *transaction.MerklePath) (p any, err error) {
	defer func() { p = recover() }()
	return nil, mp.Combine(other)
}
