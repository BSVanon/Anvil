package routeguard

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestClient_SharedAddressesCountAgainstTheGuardOnly: requests from loopback,
// private and shared addresses, and through a loopback proxy that names no
// client, may stand for many clients: no per-client cap applies to them, so
// more than ClientReadPermits of them hold read permits at once, and the
// guard warns once, whatever the address.
func TestClient_SharedAddressesCountAgainstTheGuardOnly(t *testing.T) {
	g, w := quiet(New(1<<20, 4, 64, time.Minute))
	var held []*Ticket
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.17.0.1", "100.64.0.9", "::1"} {
		for i := range ClientReadPermits + 2 {
			tk, err := begin(t, g, requestFrom(ip, 10))
			if err != nil {
				t.Fatalf("request %d from %s: %v", i, ip, err)
			}
			if tk.cl != nil {
				t.Fatalf("a request from %s was bound to client %q", ip, tk.cl.key)
			}
			held = append(held, tk)
		}
	}
	if n := w.n.Load(); n != 1 {
		t.Fatalf("warned %d times, want once", n)
	}
	for _, tk := range held {
		tk.Close()
	}
}

// TestClient_KeyFollowsTheAPIsProxyTrust: with trust_proxy off, a loopback
// proxy's rightmost X-Forwarded-For entry is the client, so one client
// behind the shipped nginx is capped and another is not; a public address's
// proxy headers are ignored, so that address is one client, and the guard
// warns once; with trust_proxy on, the entry trust_proxy_hops from the right
// is the client.
func TestClient_KeyFollowsTheAPIsProxyTrust(t *testing.T) {
	capped := func(t *testing.T, g *Guard, next func(i int) *http.Request, other *http.Request) {
		t.Helper()
		var held []*Ticket
		for i := range ClientReadPermits {
			tk, err := begin(t, g, next(i))
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			held = append(held, tk)
		}
		if _, err := begin(t, g, next(ClientReadPermits)); !errors.Is(err, ErrBusy) {
			t.Fatalf("request %d of one client: %v, want ErrBusy", ClientReadPermits+1, err)
		}
		tk, err := begin(t, g, other)
		if err != nil {
			t.Fatalf("another client: %v", err)
		}
		for _, tk := range append(held, tk) {
			tk.Close()
		}
	}
	t.Run("loopback proxy", func(t *testing.T) {
		g, w := quiet(New(1<<20, 4, 64, time.Minute))
		capped(t, g, func(i int) *http.Request {
			return requestFrom("127.0.0.1", 10, "forged-"+string(rune('a'+i))+", "+clientA)
		}, requestFrom("127.0.0.1", 10, clientB))
		if n := w.n.Load(); n != 0 {
			t.Fatalf("warned %d times for clients a loopback proxy named", n)
		}
	})
	t.Run("public address with proxy headers, trust_proxy off", func(t *testing.T) {
		g, w := quiet(New(1<<20, 4, 64, time.Minute))
		capped(t, g, func(i int) *http.Request {
			return requestFrom("198.51.100.7", 10, "203.0.113."+string(rune('1'+i)))
		}, requestFrom(clientB, 10))
		if n := w.n.Load(); n != 1 {
			t.Fatalf("warned %d times about ignored proxy headers, want once", n)
		}
	})
	t.Run("trust_proxy on, two hops", func(t *testing.T) {
		g, _ := quiet(New(1<<20, 4, 64, time.Minute))
		g.TrustProxy(true, 2)
		capped(t, g, func(i int) *http.Request {
			return requestFrom("198.51.100.7", 10, clientA+", 198.51.100."+string(rune('1'+i)))
		}, requestFrom("198.51.100.7", 10, clientB+", 198.51.100.1"))
	})
}

// TestClient_RefusedBodyIsNotWaitedFor: a client's request refused for its
// read permits is answered 503 at once and its connection closed, though its
// body never comes, while another client's is read. The clients are named in
// X-Forwarded-For by a loopback proxy, as behind the shipped nginx.
func TestClient_RefusedBodyIsNotWaitedFor(t *testing.T) {
	g, _ := quiet(New(1<<20, 4, 64, testWait))
	route := Route{MaxBody: 64 << 10, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	for range ClientReadPermits {
		rawRequest(t, srv, "POST /read HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: "+clientA+"\r\nContent-Length: 1000\r\n\r\n")
	}
	for end := time.Now().Add(5 * time.Second); refsOf(g, clientA) < ClientReadPermits; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("client A's requests never began")
		}
	}
	start := time.Now()
	conn := rawRequest(t, srv, "POST /read HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: "+clientA+"\r\nContent-Length: 1000\r\n\r\n")
	if res := nextResult(t, results, 5*time.Second); !errors.Is(res.err, ErrBusy) {
		t.Fatalf("client A's request %d: %v, want ErrBusy", ClientReadPermits+1, res.err)
	}
	code, br := answerOn(t, conn, 3*time.Second)
	if closed := closedAfter(conn, br); code != http.StatusServiceUnavailable || !closed || time.Since(start) > time.Second {
		t.Fatalf("client A's refused request: %d, closed %v, after %v; want 503 and closed at once", code, closed, time.Since(start))
	}
	honest := rawRequest(t, srv, "POST /read HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: "+clientB+"\r\nContent-Length: 5\r\n\r\nhello")
	if res := nextResult(t, results, 5*time.Second); res.err != nil || string(res.body) != "hello" {
		t.Fatalf("client B with client A at its cap: %q, %v", res.body, res.err)
	}
	if code, _ := answerOn(t, honest, 3*time.Second); code != http.StatusOK {
		t.Fatalf("client B answered %d", code)
	}
}
