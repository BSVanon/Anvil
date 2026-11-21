package api

import (
	"net/http"
	"testing"
)

// TestBRC121ARCTransientAnswerKept: a payment ARC answers with a status or an
// HTTP code that does not refuse the transaction outright (a status still on
// its way, UNKNOWN, a stale block, a form error, a server error) is answered
// 503 and kept in the journal, unrecorded: the network may still accept it.
func TestBRC121ARCTransientAnswerKept(t *testing.T) {
	for _, a := range []struct {
		status string
		code   int
	}{{"QUEUED", 0}, {"UNKNOWN", 0}, {"MINED_IN_STALE_BLOCK", 0}, {"DOUBLE_SPEND_ATTEMPTED", 0},
		{"SEEN_IN_ORPHAN_MEMPOOL", 0}, {"INVALID", 0}, {"MALFORMED", 0}, {"", 460}, {"", 503}} {
		f := newBRC121Fix(t, 100)
		f.arc.answer(a.status, a.code)
		w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
		if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept || w.Header().Get("Retry-After") == "" {
			t.Fatalf("%+v: want 503 %s, got %d %s", a, codeBRC121PaymentKept, w.Code, w.Body.String())
		}
		assertNoBRC121Offer(t, w)
		if internalizes, _ := f.wallet.recorded(); internalizes != 0 || f.journaled() != 1 {
			t.Fatalf("%+v: want the payment kept unrecorded, got %d internalizes and %d kept", a, internalizes, f.journaled())
		}
	}
}
