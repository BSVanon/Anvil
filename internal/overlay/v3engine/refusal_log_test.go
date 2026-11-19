package v3engine

import (
	"bytes"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-sdk/script"
)

// lockedBuffer is a buffer the routes' goroutines may write while a test
// reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watchRefusals makes the process-wide refusal logger, for the rest of the
// test, one that writes to the buffer returned.
func watchRefusals(t *testing.T) *lockedBuffer {
	t.Helper()
	b := &lockedBuffer{}
	prev := refusallog.SetDefault(refusallog.New(time.Hour, slog.New(slog.NewTextHandler(b, nil))))
	t.Cleanup(func() { refusallog.SetDefault(prev) })
	return b
}

// assertLogged fails unless the refusal log holds a line for status and
// reason on route, with the client's address.
func (b *lockedBuffer) assertLogged(t *testing.T, status int, reason refusallog.Reason, route string) {
	t.Helper()
	want := []string{"status=" + strconv.Itoa(status), "reason=" + string(reason), "route=" + route, "remote_addr=127.0.0.1:"}
	for _, line := range strings.Split(b.String(), "\n") {
		ok := strings.Contains(line, "refused request")
		for _, w := range want {
			ok = ok && strings.Contains(line, w)
		}
		if ok {
			return
		}
	}
	t.Errorf("the refusal log has no line with %q:\n%s", want, b.String())
}

// TestSubmit_LogsARefusedBEEF: a BEEF the guard refuses (here, a spend only
// the extended format backs) is answered 400 and logged once, with the
// route, the status, the reason and the client's address.
func TestSubmit_LogsARefusedBEEF(t *testing.T) {
	logs := watchRefusals(t)
	_, _, url := normEngine(t)
	if code, resp := postSubmit(t, url, efSpendBEEF(t, []byte{script.OpTRUE})); code != http.StatusBadRequest {
		t.Fatalf("submit: %d %s, want 400", code, resp)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonRefusedBEEF, "/submit")
}
