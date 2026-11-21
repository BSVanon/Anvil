package lookups

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestDEXSwapLookupStopsAtSharedResultLimit(t *testing.T) {
	db := newLookupDB(t)
	batch := new(leveldb.Batch)
	body, err := json.Marshal(dexSwapItem{})
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	for i := 0; i < peerhygiene.MaxLookupOutputs+1; i++ {
		var txid chainhash.Hash
		binary.LittleEndian.PutUint64(txid[:8], uint64(i+1))
		op := &transaction.Outpoint{Txid: txid, Index: uint32(i)}
		batch.Put(itemKey(dexSwapItemPrefix, &op.Txid, op.Index), body)
	}
	if err := db.Write(batch, nil); err != nil {
		t.Fatalf("seed items: %v", err)
	}
	service := NewDEXSwapLookupService(db)
	query, _ := json.Marshal(topics.DEXSwapLookupQuery{List: "all"})
	answer, err := service.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.DEXSwapLookupServiceName,
		Query:   query,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := len(answer.Formulas); got != peerhygiene.MaxLookupOutputs {
		t.Fatalf("lookup returned %d formulas, want shared cap %d", got, peerhygiene.MaxLookupOutputs)
	}
}
