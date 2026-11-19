package refusallog

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// captureHandler is a minimal slog.Handler that records every emitted record
// under a mutex, so a test can assert on level, message, and attributes
// while Logger's own mutex is held by a concurrent caller elsewhere.
type captureHandler struct {
	mu      sync.Mutex
	records *[]slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// captureLogger returns a *slog.Logger backed by captureHandler and the
// slice it appends records to. The slice must only be read after the
// producing goroutine(s) have finished — these tests call Log synchronously
// from the test goroutine, so no extra lock is needed to read it back.
func captureLogger() (*slog.Logger, *[]slog.Record) {
	var recs []slog.Record
	return slog.New(&captureHandler{records: &recs}), &recs
}

// attrMap flattens a record's attributes into a string map for easy
// assertions.
func attrMap(r slog.Record) map[string]string {
	m := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	return m
}

func testRequest(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/submit", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestLog_FirstRefusalLogsImmediately: the very first refusal of a Reason
// logs at once, with nothing suppressed before it — an operator sees the
// first occurrence without waiting out an interval.
func TestLog_FirstRefusalLogsImmediately(t *testing.T) {
	logger, recs := captureLogger()
	l := New(time.Minute, logger)
	l.Log(testRequest("203.0.113.1:5555", nil), http.StatusServiceUnavailable, ReasonBusy)

	if len(*recs) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(*recs), *recs)
	}
	attrs := attrMap((*recs)[0])
	if attrs["suppressed"] != "0" {
		t.Errorf("suppressed = %q, want %q", attrs["suppressed"], "0")
	}
	if attrs["status"] != "503" {
		t.Errorf("status = %q, want %q", attrs["status"], "503")
	}
	if attrs["reason"] != string(ReasonBusy) {
		t.Errorf("reason = %q, want %q", attrs["reason"], ReasonBusy)
	}
	if attrs["route"] != "/submit" {
		t.Errorf("route = %q, want %q", attrs["route"], "/submit")
	}
}

// TestLog_BurstWithinIntervalLogsOnceThenFlushesSuppressedCount: N refusals
// of one reason inside a single interval produce exactly one line (the
// first); the rest only accumulate a suppressed count. The next refusal
// after the interval elapses flushes that count into its own line — proving
// both that a burst is rate-limited to one line, and that the suppressed
// count the next line carries is exact.
func TestLog_BurstWithinIntervalLogsOnceThenFlushesSuppressedCount(t *testing.T) {
	logger, recs := captureLogger()
	const interval = 30 * time.Millisecond
	l := New(interval, logger)
	req := testRequest("203.0.113.2:1", nil)

	const burst = 5
	for i := 0; i < burst; i++ {
		l.Log(req, http.StatusServiceUnavailable, ReasonBusy)
	}
	if len(*recs) != 1 {
		t.Fatalf("after a %d-call burst inside one interval: got %d records, want 1: %+v", burst, len(*recs), *recs)
	}
	if got := attrMap((*recs)[0])["suppressed"]; got != "0" {
		t.Errorf("first line suppressed = %q, want %q", got, "0")
	}

	time.Sleep(interval + 15*time.Millisecond)
	l.Log(req, http.StatusServiceUnavailable, ReasonBusy)

	if len(*recs) != 2 {
		t.Fatalf("after the interval elapsed: got %d records, want 2: %+v", len(*recs), *recs)
	}
	want := burst - 1 // the burst's calls 2..5 were suppressed; call 1 already logged
	if got := attrMap((*recs)[1])["suppressed"]; got != strconv.Itoa(want) {
		t.Errorf("second line suppressed = %q, want %q", got, strconv.Itoa(want))
	}
}

// TestLog_TwoReasonsLogTwoLines: rate-limiting is keyed per Reason, not
// global — one refusal each of two different reasons inside the same
// interval still produces two lines, not one.
func TestLog_TwoReasonsLogTwoLines(t *testing.T) {
	logger, recs := captureLogger()
	l := New(time.Minute, logger)
	req := testRequest("203.0.113.3:1", nil)

	l.Log(req, http.StatusServiceUnavailable, ReasonBusy)
	l.Log(req, http.StatusRequestTimeout, ReasonSlowBody)
	// A repeat of the first reason must not add a third line.
	l.Log(req, http.StatusServiceUnavailable, ReasonBusy)

	if len(*recs) != 2 {
		t.Fatalf("got %d records for two distinct reasons, want 2: %+v", len(*recs), *recs)
	}
	seen := map[string]bool{}
	for _, r := range *recs {
		seen[attrMap(r)["reason"]] = true
	}
	if !seen[string(ReasonBusy)] || !seen[string(ReasonSlowBody)] {
		t.Errorf("reasons logged = %v, want both %q and %q", seen, ReasonBusy, ReasonSlowBody)
	}
}

// TestLog_RemoteAddrAndForwardedHeadersAppear: the request's RemoteAddr
// always appears; X-Forwarded-For and X-Real-IP appear, labelled under their
// own keys, only when the request carries them.
func TestLog_RemoteAddrAndForwardedHeadersAppear(t *testing.T) {
	logger, recs := captureLogger()
	l := New(time.Minute, logger)

	l.Log(testRequest("198.51.100.9:4242", nil), http.StatusServiceUnavailable, ReasonBusy)
	attrs := attrMap((*recs)[0])
	if attrs["remote_addr"] != "198.51.100.9:4242" {
		t.Errorf("remote_addr = %q, want %q", attrs["remote_addr"], "198.51.100.9:4242")
	}
	if _, has := attrs["x_forwarded_for"]; has {
		t.Errorf("x_forwarded_for present with no header set: %v", attrs)
	}
	if _, has := attrs["x_real_ip"]; has {
		t.Errorf("x_real_ip present with no header set: %v", attrs)
	}

	l2 := New(time.Minute, logger)
	l2.Log(testRequest("198.51.100.9:4242", map[string]string{
		"X-Forwarded-For": "203.0.113.50, 198.51.100.9",
		"X-Real-IP":       "203.0.113.50",
	}), http.StatusServiceUnavailable, ReasonBusy)
	attrs2 := attrMap((*recs)[1])
	if attrs2["x_forwarded_for"] != "203.0.113.50, 198.51.100.9" {
		t.Errorf("x_forwarded_for = %q, want the header value", attrs2["x_forwarded_for"])
	}
	if attrs2["x_real_ip"] != "203.0.113.50" {
		t.Errorf("x_real_ip = %q, want the header value", attrs2["x_real_ip"])
	}
	if attrs2["remote_addr"] != "198.51.100.9:4242" {
		t.Errorf("remote_addr = %q, want the connection address even with forwarding headers present", attrs2["remote_addr"])
	}
}

// TestLog_OverflowBucketBoundsMemory: a future caller passing far more than
// maxReasons distinct Reasons must not grow Logger.entries without bound —
// everything past maxReasons distinct keys shares the one overflow entry.
func TestLog_OverflowBucketBoundsMemory(t *testing.T) {
	logger, _ := captureLogger()
	l := New(time.Minute, logger)
	req := testRequest("203.0.113.4:1", nil)

	for i := 0; i < maxReasons+10; i++ {
		l.Log(req, http.StatusBadRequest, Reason(strconv.Itoa(i)))
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > maxReasons+1 {
		t.Fatalf("entries grew to %d, want at most %d (maxReasons + the overflow bucket)", n, maxReasons+1)
	}
}

// TestLog_PackageLevelUsesDefault proves the free function Log reaches the
// shared Default Logger, which is what every production call site uses.
func TestLog_PackageLevelUsesDefault(t *testing.T) {
	if Default() == nil {
		t.Fatal("Default is nil")
	}
	if Default().interval != DefaultInterval {
		t.Errorf("Default().interval = %v, want %v", Default().interval, DefaultInterval)
	}
	logger, recs := captureLogger()
	prev := SetDefault(New(time.Hour, logger))
	defer SetDefault(prev)
	Log(testRequest("203.0.113.9:1", nil), http.StatusBadRequest, ReasonRefusedBEEF)
	if len(*recs) != 1 || attrMap((*recs)[0])["reason"] != string(ReasonRefusedBEEF) {
		t.Errorf("Log through the Logger SetDefault installed wrote %d records", len(*recs))
	}
}
