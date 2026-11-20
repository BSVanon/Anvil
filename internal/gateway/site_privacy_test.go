package gateway

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// capturingHandler renders every record through a real slog.TextHandler
// into buf, so a test can grep the exact formatted output rather than
// trust a hand-rolled summary of it.
type capturingHandler struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
	h   slog.Handler
}

func newCapturingHandler() (*capturingHandler, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &capturingHandler{mu: &sync.Mutex{}, buf: buf, h: slog.NewTextHandler(buf, nil)}, buf
}

func (c *capturingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return c.h.Enabled(ctx, level)
}

func (c *capturingHandler) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.h.Handle(ctx, r)
}

func (c *capturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &capturingHandler{mu: c.mu, buf: c.buf, h: c.h.WithAttrs(attrs)}
}

func (c *capturingHandler) WithGroup(name string) slog.Handler {
	return &capturingHandler{mu: c.mu, buf: c.buf, h: c.h.WithGroup(name)}
}

// TestSiteHandler_NoLogPrivacy is decision 8's no-log test: capture every
// log line written while serving requests that carry a distinctive IP,
// User-Agent and path, and assert none of those literal values ever reach
// the log — including on the one line decision 8 does allow (a
// content-fetch failure, which logs the txid only).
func TestSiteHandler_NoLogPrivacy(t *testing.T) {
	handler, buf := newCapturingHandler()
	logger := slog.New(handler)

	origin := testOutpoint(880, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	policy, _, _ := newTestPolicy(t, "domain privacy.example.org\n", fake)

	const distinctiveIP = "203.0.113.42"
	const distinctiveUA = "ExampleBrowser/9.9.9 PrivacyProbe"
	const distinctivePathSegment = "super_secret_path_segment"

	// A normal, successful request: must log nothing at all.
	okHandler := NewSiteHandler(SiteHandlerConfig{
		Policy:       policy,
		Content:      &fakeContent{data: []byte("hi"), ct: "text/plain"},
		ContentScope: "any",
		Logger:       logger,
	})
	req1 := httptest.NewRequest("GET", "http://privacy.example.org/content/does-not-parse-"+distinctivePathSegment, nil)
	req1.Host = "privacy.example.org"
	req1.RemoteAddr = distinctiveIP + ":12345"
	req1.Header.Set("User-Agent", distinctiveUA)
	w1 := httptest.NewRecorder()
	okHandler.ServeHTTP(w1, req1)

	// A request that DOES trigger decision 8's one allowed log line (a
	// content-fetch failure) — the txid it logs is the configured origin's,
	// never anything from the request itself.
	failHandler := NewSiteHandler(SiteHandlerConfig{
		Policy:       policy,
		Content:      &fakeContent{err: fmt.Errorf("boom")},
		ContentScope: "any",
		Logger:       logger,
	})
	req2 := httptest.NewRequest("GET", "http://privacy.example.org/", nil)
	req2.Host = "privacy.example.org"
	req2.RemoteAddr = distinctiveIP + ":12345"
	req2.Header.Set("User-Agent", distinctiveUA)
	w2 := httptest.NewRecorder()
	failHandler.ServeHTTP(w2, req2)

	logged := buf.String()
	if strings.Contains(logged, distinctiveIP) {
		t.Fatalf("log output must never contain the client IP, got: %s", logged)
	}
	if strings.Contains(logged, distinctiveUA) {
		t.Fatalf("log output must never contain the User-Agent, got: %s", logged)
	}
	if strings.Contains(logged, distinctivePathSegment) {
		t.Fatalf("log output must never contain the request path, got: %s", logged)
	}
	// Sanity: the fetch-failure line did fire, so this test isn't vacuous.
	if !strings.Contains(logged, "gateway content fetch failed") {
		t.Fatalf("expected the content-fetch-failure line to have logged, got: %s", logged)
	}
}
