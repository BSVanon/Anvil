package v3engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
)

// lookupAs sends an honest lookup on a client of its own as client, whom a
// loopback proxy names in X-Forwarded-For, as the shipped nginx does, and
// returns the status and the time taken.
func lookupAs(t *testing.T, url, client string) (int, time.Duration) {
	t.Helper()
	q, _ := json.Marshal(map[string]any{"service": topics.UHRPLookupServiceName, "query": topics.UHRPLookupQuery{ContentHash: fmt.Sprintf("%064x", 0xabc0000)}})
	req, _ := http.NewRequest(http.MethodPost, url+"/lookup", bytes.NewReader(q))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", client)
	hc := &http.Client{Transport: &http.Transport{}, Timeout: 30 * time.Second}
	defer hc.CloseIdleConnections()
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("lookup as %s: %v", client, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

// TestGuard_OneClientCannotHoldEveryReadPermit (cold review round 4 RISK 3,
// single source): one client that opens routeguard.ReadPermits header-only
// connections, named in X-Forwarded-For by a loopback proxy, holds at most
// routeguard.ClientReadPermits read permits: the rest are answered 503 and
// closed at once, those it holds are cut 408 at the grace, and another
// client's lookups are answered 200 within honestBound meanwhile, as is one
// from the loopback address itself. From an address no proxy names, the same
// connections hold every permit and turn other lookups away
// (TestGuard_ReadPermitsBoundIdleConnections).
func TestGuard_OneClientCannotHoldEveryReadPermit(t *testing.T) {
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	opened := time.Now()
	conns := make([]net.Conn, routeguard.ReadPermits)
	for i := range conns {
		conns[i] = idlePost(t, url, "/lookup", 10, "X-Forwarded-For: 203.0.113.1\r\n", nil)
	}
	time.Sleep(300 * time.Millisecond)
	for i := range 3 {
		code, took := lookupAs(t, url, "203.0.113.2")
		t.Logf("client B's lookup %d with client A's %d connections open: %d in %v", i, len(conns), code, took)
		if code != http.StatusOK || took > honestBound {
			t.Errorf("client B's lookup %d: %d in %v, want 200 within %v", i, code, took, honestBound)
		}
	}
	if code, _, took := honestLookup(t, url); code != http.StatusOK || took > honestBound {
		t.Errorf("a lookup from the loopback address itself: %d in %v, want 200 within %v", code, took, honestBound)
	}
	if since := time.Since(opened); since >= bodyread.ReadGrace {
		t.Fatalf("the lookups ended %v after client A's connections opened, past the grace", since)
	}
	refused, cut := 0, 0
	for i, conn := range conns {
		code, closed := cutAnswer(t, conn, bodyread.ReadGrace+3*time.Second)
		switch {
		case code == http.StatusServiceUnavailable && closed:
			refused++
		case code == http.StatusRequestTimeout && closed:
			cut++
		default:
			t.Fatalf("client A's connection %d: %d, closed %v; want 503 or 408, closed", i, code, closed)
		}
	}
	t.Logf("client A's %d connections: %d answered 503 and closed, %d cut 408 at the grace, all by %v", len(conns), refused, cut, time.Since(opened))
	if cut != routeguard.ClientReadPermits || refused != len(conns)-cut {
		t.Fatalf("%d connections held a read permit, want %d", cut, routeguard.ClientReadPermits)
	}
}
