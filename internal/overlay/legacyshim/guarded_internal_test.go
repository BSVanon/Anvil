package legacyshim

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// internalLogs is a small, local stand-in for legacyshim_test's legacyLogs
// (refusal_log_test.go): writeLegacyGuardError is unexported, so proving
// what it logs needs an internal (package legacyshim) test file, which
// cannot see that external package's helpers. This repeats their shape
// rather than exporting them just for this one test.
type internalLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *internalLogs) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func watchRefusalsInternal(t *testing.T) *internalLogs {
	t.Helper()
	b := &internalLogs{}
	prev := refusallog.SetDefault(refusallog.New(time.Hour, slog.New(slog.NewTextHandler(b, nil))))
	t.Cleanup(func() { refusallog.SetDefault(prev) })
	return b
}

func (b *internalLogs) assertLogged(t *testing.T, status int, reason refusallog.Reason, route string) {
	t.Helper()
	b.mu.Lock()
	logged := b.buf.String()
	b.mu.Unlock()
	want := []string{"status=" + strconv.Itoa(status), "reason=" + string(reason), "route=" + route}
	for _, line := range strings.Split(logged, "\n") {
		ok := strings.Contains(line, "refused request")
		for _, w := range want {
			ok = ok && strings.Contains(line, w)
		}
		if ok {
			return
		}
	}
	t.Errorf("the refusal log has no line with %q:\n%s", want, logged)
}

// TestWriteLegacyGuardError_ClassifiesInvalidTransaction: writeLegacyGuardError's
// default branch used to log every otherwise-unnamed error, including a
// genuinely invalid transaction (engine.ErrInvalidTransaction or
// engine.ErrInvalidBeef) under the same ReasonOtherGuardError as any other
// unclassified guard failure, and answered
// a bare verification-stage error (statusForSubmitError's generic case) with
// a 500. It now logs the two named engine sentinels under their own
// ReasonInvalidTransaction with their status unchanged (422, from
// statusForSubmitError), and reclassifies any other error that would have
// fallen to statusForSubmitError's generic 500 -- a plain spv.Verify script,
// fee or merkle failure, unwrapped by routeguard/verify.go's final switch
// -- as an invalid transaction too, answered 400
// with invalidTransactionCode instead of 500.
func TestWriteLegacyGuardError_ClassifiesInvalidTransaction(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/overlay/submit", nil)
	r.RemoteAddr = "127.0.0.1:9"

	logs := watchRefusalsInternal(t)
	w := httptest.NewRecorder()
	writeLegacyGuardError(w, r, engine.ErrInvalidTransaction)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ErrInvalidTransaction: status = %d, want 422 (statusForSubmitError, unchanged by the reason classification)", w.Code)
	}
	logs.assertLogged(t, http.StatusUnprocessableEntity, refusallog.ReasonInvalidTransaction, "/overlay/submit")

	logs = watchRefusalsInternal(t)
	w = httptest.NewRecorder()
	writeLegacyGuardError(w, r, engine.ErrInvalidBeef)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ErrInvalidBeef: status = %d, want 422", w.Code)
	}
	logs.assertLogged(t, http.StatusUnprocessableEntity, refusallog.ReasonInvalidTransaction, "/overlay/submit")

	logs = watchRefusalsInternal(t)
	w = httptest.NewRecorder()
	writeLegacyGuardError(w, r, errors.New("some other guard failure"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("other error: status = %d, want 400 (reclassified as an invalid transaction, not statusForSubmitError's generic 500)", w.Code)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonInvalidTransaction, "/overlay/submit")

	logs = watchRefusalsInternal(t)
	w = httptest.NewRecorder()
	writeLegacyGuardError(w, r, engine.ErrUnknownTopic)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ErrUnknownTopic: status = %d, want 400 (statusForSubmitError's own named case, not the reclassification)", w.Code)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonOtherGuardError, "/overlay/submit")
}
