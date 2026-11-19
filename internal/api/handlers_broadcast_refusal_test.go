package api

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// refusalBuffer is a buffer a handler may write while a test reads it.
type refusalBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *refusalBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *refusalBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// emptyTxsBEEF is a V2 BEEF of n distinct empty transactions.
func emptyTxsBEEF(n int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(transaction.BEEF_V2))
	b.WriteByte(0) // no BUMPs
	b.WriteByte(0xfe)
	_ = binary.Write(&b, binary.LittleEndian, uint32(n))
	for i := 0; i < n; i++ {
		b.WriteByte(0) // raw transaction, no BUMP
		_ = binary.Write(&b, binary.LittleEndian, uint32(i+1))
		b.WriteByte(0) // no inputs
		b.WriteByte(0) // no outputs
		_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	}
	return b.Bytes()
}

// TestBroadcast_LogsATooComplexRefusal: a BEEF over beefscan's cap is
// answered 422 and logged once under its own reason, with the client's
// address; a BEEF refused for any other reason is answered 422 too, but not
// logged under that reason.
func TestBroadcast_LogsATooComplexRefusal(t *testing.T) {
	var logs refusalBuffer
	prev := refusallog.SetDefault(refusallog.New(time.Hour, slog.New(slog.NewTextHandler(&logs, nil))))
	t.Cleanup(func() { refusallog.SetDefault(prev) })
	srv := testServerGullible(t)

	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/broadcast", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		req.RemoteAddr = "203.0.113.7:4242"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	if w := post([]byte{0xde, 0xad, 0xbe, 0xef}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("garbage: %d %s, want 422", w.Code, w.Body.String())
	}
	if got := logs.String(); got != "" {
		t.Fatalf("a refusal that is not too complex was logged: %q", got)
	}
	w := post(emptyTxsBEEF(beefscan.Default.Txs + 1))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), beefscan.Code) {
		t.Fatalf("over the cap: %d %s, want 422 with %s", w.Code, w.Body.String(), beefscan.Code)
	}
	line := logs.String()
	for _, want := range []string{"refused request", "status=422", "reason=" + string(refusallog.ReasonBroadcastTooComplex), "route=/broadcast", "remote_addr=203.0.113.7:4242"} {
		if !strings.Contains(line, want) {
			t.Errorf("refusal log %q lacks %q", line, want)
		}
	}
}
