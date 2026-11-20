package routeguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// Two clients, by the TEST-NET-3 addresses the guard counts as public.
const clientA, clientB = "203.0.113.1", "203.0.113.2"

// warnings counts the guard's rate-limited warnings and keeps their text.
type warnings struct {
	n    atomic.Int32
	mu   sync.Mutex
	msgs []string
}

func (w *warnings) warn(msg string, args ...any) {
	w.n.Add(1)
	w.mu.Lock()
	w.msgs = append(w.msgs, msg)
	w.mu.Unlock()
}

// last is the most recent warning's text, or "" when none has fired.
func (w *warnings) last() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.msgs) == 0 {
		return ""
	}
	return w.msgs[len(w.msgs)-1]
}

// quiet returns g with its warnings counted rather than logged.
func quiet(g *Guard) (*Guard, *warnings) {
	w := &warnings{}
	g.clients.warn = w.warn
	return g, w
}

// requestFrom is a POST with a body of n bytes declared, from remote, with the
// X-Forwarded-For values xff.
func requestFrom(remote string, n int64, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/lookup", nil)
	r.RemoteAddr = net.JoinHostPort(remote, "5555")
	r.ContentLength = n
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

// begin starts a ticket bound to r's client, as Begin itself does now.
func begin(t *testing.T, g *Guard, r *http.Request) (*Ticket, error) {
	t.Helper()
	return g.Begin(httptest.NewRecorder(), r, false)
}

// beginLoopback is Begin for a test that cares only about the guard's own
// budgets, not a client's: a fresh loopback request each call, which binds
// to no client (clientkey.Shared), so Begin behaves as it did before
// per-client caps existed.
func beginLoopback(g *Guard, jsonRoute bool) (*Ticket, error) {
	return g.Begin(httptest.NewRecorder(), requestFrom("127.0.0.1", 10), jsonRoute)
}

// ticketOf is a ticket of client ip whose body is in: begun, bound to ip, and
// its read permits returned.
func ticketOf(g *Guard, ip string) (*Ticket, error) {
	tk, err := g.Begin(httptest.NewRecorder(), requestFrom(ip, 10), false)
	if err != nil {
		return nil, err
	}
	tk.leave(slotRead)
	return tk, nil
}

// beginAs is ticketOf, failing the test when it fails.
func beginAs(t *testing.T, g *Guard, ip string) *Ticket {
	t.Helper()
	tk, err := ticketOf(g, ip)
	if err != nil {
		t.Fatalf("a ticket of %s: %v", ip, err)
	}
	return tk
}

// refsOf is how many tickets and hand-offs refer to client key.
func refsOf(g *Guard, key string) int {
	g.clients.mu.Lock()
	defer g.clients.mu.Unlock()
	if c := g.clients.byKey[key]; c != nil {
		return c.refs
	}
	return 0
}
