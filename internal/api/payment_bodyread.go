package api

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// bodyReadDeadline bounds how long issueChallengeForPayees waits to read a
// request body before it reserves a pending-place slot (payment_pending.go).
// A var, not a const, so a test can shrink it — same pattern as
// sseWriteDeadline (sse_deadline.go) and nonceScriptTimeout
// (payment_bounds.go) already in this package.
//
// cold review round 4's RISK 2: reservePending used to run before this read,
// so a connection that sent its headers and then stalled the body (a
// slow-loris — one byte an hour, or simply never) held its pending-place
// slot for as long as the stall lasted, with no bound at all: net/http sets
// no default per-read timeout on a request body. With maxPendingChallenges
// (1,024) slots total, 1,024 such connections starved every legitimate
// challenge request. Reading the body first, under its own deadline, means
// a stalled read costs only a goroutine and a timeout — it never reserves a
// slot at all, so no number of slow-body connections can exhaust the pool.
var bodyReadDeadline = 10 * time.Second

// readChallengeBody reads r's body under the existing 1 MiB cap
// (issueChallengeForPayees always applied this limit, just later) and
// bodyReadDeadline, before any pending-place slot is reserved. On success it
// resets r.Body to a fresh reader over the bytes read, so the later
// X402-Proof's live body hash (verifyProof) still sees them, and returns
// ok=true. On a deadline or any other read error it writes a 408 response
// itself and returns ok=false — the caller must return immediately without
// ever calling reservePending.
func readChallengeBody(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadDeadline))
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	// Clear the deadline regardless of outcome — best-effort: a
	// ResponseWriter with no real deadline support (e.g. httptest's
	// recorder) just no-ops both calls, same as writeSSE's pattern.
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		writeError(w, http.StatusRequestTimeout, "request body did not arrive in time")
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, true
}
