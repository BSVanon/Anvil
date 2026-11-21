package v3engine

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
)

// probeResult is one idle probe connection's outcome: the status Begin's own
// refusal answered with, whether the server then closed the connection, and
// how long the answer took to arrive.
type probeResult struct {
	status int
	closed bool
	took   time.Duration
	err    error
}

// probeBeginRefusal opens a connection that declares a body it never sends,
// the same shape idlePost opens, reads whatever answer comes within limit,
// and reports whether the connection was then closed — all without calling
// into testing.T, since this runs on its own goroutine and T.Fatal is not
// safe there.
func probeBeginRefusal(url, path string, n int, limit time.Duration) probeResult {
	start := time.Now()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		return probeResult{err: err}
	}
	defer conn.Close()
	req := "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nx-topics: [\"" + topics.UHRPTopicName + "\"]\r\nContent-Length: " + strconv.Itoa(n) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return probeResult{err: err}
	}
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return probeResult{err: err}
	}
	took := time.Since(start)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, rerr := conn.Read(b[:])
	return probeResult{status: resp.StatusCode, closed: errors.Is(rerr, io.EOF), took: took}
}

// settledGoroutines polls runtime.NumGoroutine until it stops falling for
// five readings in a row, up to 10s, and returns the last reading — a
// connection the server just closed may still be finishing teardown (the
// read loop, the response writer) a moment after the client observed EOF,
// and that teardown is not perfectly monotonic tick to tick.
func settledGoroutines() int {
	last := runtime.NumGoroutine()
	flat := 0
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= last {
			if flat++; flat >= 5 {
				return n
			}
		} else {
			flat = 0
		}
		last = n
	}
	return last
}

// TestGuard_BusyBeginRefusesAnUnsentBodyPromptly reproduces cold review round
// 4's B4a RISK 1 exactly: routeguard.ReadPermits idle connections hold every
// read permit, so Begin fails with ErrBusy for the next arrival before
// ReadBody ever runs — at that point nothing has read the connection past
// its declared body, and nothing but this fix told the server to give it up.
// 300 further connections, each declaring a 100-byte body and sending none
// of it, must all still get an answer and be closed, and the goroutine count
// must return to its baseline once every connection (holding and probing
// alike) has been answered — not grow by one per probe, which is what a
// Begin error that never calls routeguard.Refuse does: the connection
// lingers, since nothing has read past its body for net/http's own idle
// keep-alive handling to find the end of.
func TestGuard_BusyBeginRefusesAnUnsentBodyPromptly(t *testing.T) {
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	if code, _, _ := honestLookup(t, url); code != http.StatusOK {
		t.Fatalf("honest lookup with no idle connection: %d", code)
	}

	baseline := settledGoroutines()

	holding := make([]net.Conn, routeguard.ReadPermits)
	for i := range holding {
		holding[i] = idlePost(t, url, "/lookup", 10, "", nil)
	}
	time.Sleep(300 * time.Millisecond) // let every holding connection's Begin land

	const probes = 300
	const perProbeBound = 2 * time.Second // ErrBusy answers "at once" (measured ~ms); -race and scheduling noise get real margin
	results := make([]probeResult, probes)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = probeBeginRefusal(url, "/submit", 100, perProbeBound)
		}(i)
	}
	wg.Wait()

	var answered, closed int
	var slowest time.Duration
	for i, r := range results {
		if r.err != nil {
			t.Errorf("probe %d: %v, want an answer within %v", i, r.err, perProbeBound)
			continue
		}
		answered++
		if r.closed {
			closed++
		}
		if r.took > slowest {
			slowest = r.took
		}
		if r.status != http.StatusServiceUnavailable {
			t.Errorf("probe %d: status %d, want 503 (ErrBusy — every read permit is held)", i, r.status)
		}
	}
	t.Logf("%d/%d probes answered, %d/%d closed after their answer, slowest answer %v", answered, probes, closed, probes, slowest)
	if answered != probes {
		t.Fatalf("%d/%d probes got no answer within %v", probes-answered, probes, perProbeBound)
	}
	if closed != probes {
		t.Fatalf("%d/%d answered probes were not closed", probes-closed, probes)
	}

	for i, conn := range holding {
		if code, ok := cutAnswer(t, conn, bodyread.ReadGrace+3*time.Second); code != http.StatusRequestTimeout || !ok {
			t.Fatalf("holding connection %d: %d, closed %v; want 408 and closed", i, code, ok)
		}
	}

	after := settledGoroutines()
	t.Logf("goroutines: %d before, %d after %d holding + %d probe connections were all answered and closed", baseline, after, len(holding), probes)
	if after > baseline+5 {
		t.Errorf("goroutines settled at %d, want close to the %d baseline (a lingering refusal pins one per unanswered connection)", after, baseline)
	}
}
