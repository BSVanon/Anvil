package api

import (
	"net/http"
	"testing"
)

// TestBRC121ARCTransientAnswerKept: a payment ARC answers with a status or an
// HTTP code that does not refuse the transaction outright (a status still on
// its way, UNKNOWN, a stale block, a form error, a server error) is answered
// 402 and kept in the journal, unrecorded: the network may still accept it.
func TestBRC121ARCTransientAnswerKept(t *testing.T) {
	for _, a := range []struct {
		status string
		code   int
	}{{"QUEUED", 0}, {"UNKNOWN", 0}, {"MINED_IN_STALE_BLOCK", 0}, {"", 460}, {"", 503}} {
		f := newBRC121Fix(t, 100)
		f.arc.answer(a.status, a.code)
		w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
		if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121NotAccepted {
			t.Fatalf("%+v: want 402 %s, got %d %s", a, codeBRC121NotAccepted, w.Code, w.Body.String())
		}
		if internalizes, _ := f.wallet.recorded(); internalizes != 0 || f.journaled() != 1 {
			t.Fatalf("%+v: want the payment kept unrecorded, got %d internalizes and %d kept", a, internalizes, f.journaled())
		}
	}
}
