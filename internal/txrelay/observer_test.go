package txrelay

import (
	"bytes"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestObserverSeesEveryAdmittedTransaction(t *testing.T) {
	b := testBroadcaster()
	type seen struct {
		txid string
		beef []byte
	}
	var got []seen
	b.SetObserver(func(tx *transaction.Transaction, beef []byte) {
		got = append(got, seen{tx.TxID().String(), beef})
	})

	beef := buildTestBEEF(t)
	res, err := b.BroadcastBEEF(beef)
	if err != nil {
		t.Fatal(err)
	}
	raw := buildChildWithParent(t).Bytes()
	rawRes, err := b.BroadcastRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].txid != res.TxID || !bytes.Equal(got[0].beef, beef) || got[1].txid != rawRes.TxID || got[1].beef != nil {
		t.Fatalf("observed %+v", got)
	}

	// A transaction that fails to parse is not admitted, so not observed.
	if _, err := b.BroadcastRaw([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected a parse error")
	}
	b.SetObserver(nil)
	if _, err := b.BroadcastBEEF(beef); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("observed %d after the observer was removed", len(got))
	}
}
