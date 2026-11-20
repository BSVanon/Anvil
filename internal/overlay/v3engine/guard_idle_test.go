package v3engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/refusallog"
)

// honestBound is how long an honest lookup may take while idle connections
// are open: a quarter of routeguard.Wait, so a lookup that had to wait for
// the guard at all fails it. Unhindered, one takes about a millisecond here.
const honestBound = routeguard.Wait / 4

// idlePost opens a connection to the server at url that sends the headers of
// a POST to path declaring a body of n bytes, with extra header lines, then
// sent, and nothing more.
func idlePost(t *testing.T, url, path string, n int, extra string, sent []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n%sContent-Length: %d\r\n\r\n", path, extra, n)
	if _, err := conn.Write(sent); err != nil {
		t.Fatal(err)
	}
	return conn
}

// honestLookup sends a well-formed lookup question, its body at once, on a
// client of its own, and returns the status, Retry-After and the time taken.
func honestLookup(t *testing.T, url string) (int, string, time.Duration) {
	t.Helper()
	q, _ := json.Marshal(map[string]any{"service": topics.UHRPLookupServiceName, "query": topics.UHRPLookupQuery{ContentHash: fmt.Sprintf("%064x", 0xabc0000)}})
	client := &http.Client{Transport: &http.Transport{}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	start := time.Now()
	resp, err := client.Post(url+"/lookup", "application/json", bytes.NewReader(q))
	if err != nil {
		t.Fatalf("honest lookup: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Retry-After"), time.Since(start)
}

// cutAnswer reads the server's answer on an idle connection, waiting at most
// limit, and reports whether the server then closed the connection.
func cutAnswer(t *testing.T, conn net.Conn, limit time.Duration) (int, bool) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer on the idle connection: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = br.ReadByte()
	return resp.StatusCode, errors.Is(err, io.EOF)
}

// TestGuard_IdleConnectionsDoNotRefuseHonestLookups: connections that send
// only their headers, or a first KiB and then nothing, hold neither the heap
// budget nor the JSON slots while they wait, so honest lookups sent one at a
// time while they are open are answered 200 within honestBound. Each idle
// connection is answered 408 and closed once bodyread.ReadGrace has passed
// with no byte, or the stalled one once its first KiB no longer covers the
// pace of a 16 MiB body (routeguard.Route.MinRate). With the guard of cfa383a
// the first two cases answered every honest lookup 503, at 2.0 s and at once.
func TestGuard_IdleConnectionsDoNotRefuseHonestLookups(t *testing.T) {
	submit := "x-topics: [\"" + topics.UHRPTopicName + "\"]\r\n"
	stalled := bodyread.ReadGrace + (1<<10)*time.Second/time.Duration(routeguard.BEEFRoute.MinRate(16<<20))
	for _, c := range []struct {
		name string
		open func(t *testing.T, url string) []net.Conn
		cut  time.Duration // when the idle connections are due to be cut
	}{
		{"a 16 MiB submit and a 200,000-byte lookup, headers only", func(t *testing.T, url string) []net.Conn {
			return []net.Conn{idlePost(t, url, "/submit", 16<<20, submit, nil), idlePost(t, url, "/lookup", 200_000, "", nil)}
		}, bodyread.ReadGrace},
		{"64 lookups, headers only", func(t *testing.T, url string) []net.Conn {
			var conns []net.Conn
			for range routeguard.JSONSlots {
				conns = append(conns, idlePost(t, url, "/lookup", 10, "", nil))
			}
			return conns
		}, bodyread.ReadGrace},
		{"a 16 MiB submit that stalls after 1 KiB", func(t *testing.T, url string) []net.Conn {
			return []net.Conn{idlePost(t, url, "/submit", 16<<20, submit, make([]byte, 1<<10))}
		}, stalled},
	} {
		t.Run(c.name, func(t *testing.T) {
			eng, _ := newTestEngine(t)
			url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
			if code, _, _ := honestLookup(t, url); code != http.StatusOK {
				t.Fatalf("honest lookup with no idle connection: %d", code)
			}
			opened := time.Now()
			conns := c.open(t, url)
			time.Sleep(200 * time.Millisecond)
			for i := range 3 {
				code, _, took := honestLookup(t, url)
				t.Logf("honest lookup %d with %d idle connections open: %d in %v", i, len(conns), code, took)
				if code != http.StatusOK || took > honestBound {
					t.Errorf("honest lookup %d: %d in %v, want 200 within %v", i, code, took, honestBound)
				}
			}
			if since := time.Since(opened); since >= bodyread.ReadGrace {
				t.Fatalf("the honest lookups ended %v after the idle connections opened, past the grace", since)
			}
			var last time.Duration
			for i, conn := range conns {
				code, closed := cutAnswer(t, conn, c.cut+3*time.Second)
				last = time.Since(opened)
				if code != http.StatusRequestTimeout || !closed || last < c.cut || last > c.cut+time.Second {
					t.Fatalf("idle connection %d: %d, closed %v, %v after it opened; want 408 and closed at about %v", i, code, closed, last, c.cut)
				}
			}
			t.Logf("%d idle connections answered 408 and closed, the last %v after they opened (due %v)", len(conns), last, c.cut)
		})
	}
}

// liveMemory is the heap the process holds live, and its goroutine stacks,
// after a garbage collection.
func liveMemory() (heap, stacks uint64) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.StackInuse
}

// TestGuard_ReadPermitsBoundIdleConnections: once routeguard.ReadPermits
// connections are waiting for their bodies, the next request is refused 503
// with Retry-After at once, the bound on what idle connections may hold;
// once their grace has passed they are cut and requests are served again.
// It logs the memory the idle connections held, both ends of each in this
// process, which routeguard.ReadPermits' comment cites.
func TestGuard_ReadPermitsBoundIdleConnections(t *testing.T) {
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	if code, _, _ := honestLookup(t, url); code != http.StatusOK {
		t.Fatalf("honest lookup with no idle connection: %d", code)
	}
	logs := watchRefusals(t)
	heap0, stacks0 := liveMemory()
	opened := time.Now()
	conns := make([]net.Conn, routeguard.ReadPermits)
	for i := range conns {
		conns[i] = idlePost(t, url, "/lookup", 10, "", nil)
	}
	time.Sleep(300 * time.Millisecond)
	heap1, stacks1 := liveMemory()
	n := uint64(len(conns))
	t.Logf("%d idle connections: %.1f KiB live heap and %.1f KiB of stacks each, %.2f MiB in all",
		n, float64(heap1-heap0)/float64(n)/1024, float64(stacks1-stacks0)/float64(n)/1024, float64(heap1-heap0+stacks1-stacks0)/(1<<20))
	code, retry, took := honestLookup(t, url)
	if code != http.StatusServiceUnavailable || retry == "" || took > honestBound {
		t.Fatalf("a lookup with every read permit held: %d, Retry-After %q, in %v; want 503 with Retry-After at once", code, retry, took)
	}
	if since := time.Since(opened); since >= bodyread.ReadGrace {
		t.Fatalf("measured %v after the idle connections opened, past the grace", since)
	}
	for i, conn := range conns {
		if code, closed := cutAnswer(t, conn, bodyread.ReadGrace+3*time.Second); code != http.StatusRequestTimeout || !closed {
			t.Fatalf("idle connection %d: %d, closed %v; want 408 and closed", i, code, closed)
		}
	}
	t.Logf("all %d cut %v after they opened", n, time.Since(opened))
	if code, _, took := honestLookup(t, url); code != http.StatusOK {
		t.Fatalf("a lookup once the idle connections were cut: %d in %v", code, took)
	}
	logs.assertLogged(t, http.StatusServiceUnavailable, refusallog.ReasonBusy, "/lookup")
	logs.assertLogged(t, http.StatusRequestTimeout, refusallog.ReasonSlowBody, "/lookup")
}
