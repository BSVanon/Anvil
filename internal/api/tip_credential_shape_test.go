package api

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/bsv-blockchain/go-sdk/script"
)

func TestTipCredentialBoundsNonTokenOutputs(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	fund := f.fund(10_000)
	junk := bytes.Repeat([]byte{0xab}, 100_000)
	opret := &script.Script{}
	if err := opret.AppendOpcodes(script.OpFALSE, script.OpRETURN); err != nil {
		t.Fatal(err)
	}
	if err := opret.AppendPushData(junk); err != nil {
		t.Fatal(err)
	}
	tx := f.w.Spend(t,
		[]ordtracktest.In{{Tx: f.origin, Vout: 0}, {Tx: fund}},
		f.inscribed("carrier"), ordtracktest.Out{Sats: 9_999}, ordtracktest.Out{Sats: 0, Script: opret},
	)
	f.store.Add(tx)
	beef := ordtracktest.AtomicBEEF(t, tx)
	got := post(f.srv, beef, nil)
	sameReply(t, "oversized non-token output", got, post(f.plain, beef, nil))
	if f.srv.broadcaster.Mempool().Has(tx.TxID().String()) || f.tip() != op(f.origin, 0) {
		t.Fatal("oversized non-token output used the free path")
	}
}

func TestTipCredentialBoundsNonTokenOutputCount(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	fund := f.fund(10_000)
	outs := []ordtracktest.Out{f.inscribed("carrier")}
	for i := 0; i < 4; i++ {
		outs = append(outs, ordtracktest.Out{Sats: 1})
	}
	outs = append(outs, ordtracktest.Out{Sats: 9_995})
	tx := f.w.Spend(t, []ordtracktest.In{{Tx: f.origin, Vout: 0}, {Tx: fund}}, outs...)
	f.store.Add(tx)
	beef := ordtracktest.AtomicBEEF(t, tx)
	got := post(f.srv, beef, nil)
	sameReply(t, "too many non-token outputs", got, post(f.plain, beef, nil))
	if got.Code != http.StatusPaymentRequired || f.srv.broadcaster.Mempool().Has(tx.TxID().String()) {
		t.Fatalf("response %d; transaction broadcast=%v", got.Code, f.srv.broadcaster.Mempool().Has(tx.TxID().String()))
	}
}

func TestTipCredentialAllowsFourSmallNonTokenOutputs(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	fund := f.fund(10_000)
	outs := []ordtracktest.Out{f.inscribed("carrier")}
	for i := 0; i < 3; i++ {
		outs = append(outs, ordtracktest.Out{Sats: 1})
	}
	outs = append(outs, ordtracktest.Out{Sats: 9_996})
	tx := f.w.Spend(t, []ordtracktest.In{{Tx: f.origin, Vout: 0}, {Tx: fund}}, outs...)
	f.store.Add(tx)
	rec := post(f.srv, ordtracktest.AtomicBEEF(t, tx), nil)
	if rec.Code != http.StatusOK || f.tip() != op(tx, 0) {
		t.Fatalf("four non-token outputs: %d %s, tip %s", rec.Code, rec.Body.String(), f.tip())
	}
}

func TestTipCredentialDoesNotLimitTheTokenOutputScript(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	tx := f.move(f.w, f.origin, 0, f.inscribed(string(bytes.Repeat([]byte("v"), 1_000))))
	if len(*tx.Outputs[0].LockingScript) <= 200 {
		t.Fatal("token script is not large enough for the test")
	}
	rec := post(f.srv, ordtracktest.AtomicBEEF(t, tx), nil)
	if rec.Code != http.StatusOK || f.tip() != op(tx, 0) {
		t.Fatalf("large token output: %d %s, tip %s", rec.Code, rec.Body.String(), f.tip())
	}
}
