package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestTipCredentialDoesNotUpgradeBareV2BEEF(t *testing.T) {
	f := newTipFixture(t, "test-token", 0)
	v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
	beefV2, err := transaction.NewBeefFromTransaction(v1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := beefV2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	gate := post(f.plain, raw, map[string]string{"X-Anvil-Auth": "test-token"})
	if gate.Code != http.StatusUnprocessableEntity || !strings.Contains(gate.Body.String(), "a V2 BEEF is accepted only inside an Atomic BEEF") {
		t.Fatalf("token gate: %d %s", gate.Code, gate.Body.String())
	}
	got := post(f.srv, raw, nil)
	sameReply(t, "bare V2", got, post(f.plain, raw, nil))
	if f.tip() != op(f.origin, 0) || f.srv.broadcaster.Mempool().Has(v1.TxID().String()) {
		t.Fatal("bare V2 BEEF used the free path")
	}
}
