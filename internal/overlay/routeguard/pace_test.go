package routeguard

import (
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// TestPaceRate_TheRoutesRates: a body is paced at MinBodyRate, or at
// BigBodyRate when it is over BigBody, unless it is too long to arrive within
// its route's read timeout at that rate, and then at the rate that brings it
// in just by the timeout.
func TestPaceRate_TheRoutesRates(t *testing.T) {
	for _, c := range []struct {
		name  string
		route Route
		n     int64
		want  int64
	}{
		{"a 1 MB submit", BEEFRoute, 1_000_000, MinBodyRate},
		{"a submit of BigBody bytes", BEEFRoute, BigBody, MinBodyRate},
		{"a submit over BigBody", BEEFRoute, BigBody + 1, BigBodyRate},
		{"the longest submit BigBodyRate covers", BEEFRoute, BigBodyRate * 118, BigBodyRate},
		{"a 16 MiB submit", BEEFRoute, 16 << 20, 142_180}, // 16 MiB / 118 s, rounded up
		{"a lookup question", LookupRoute, 1_000, MinBodyRate},
		{"a 1 MiB lookup", LookupRoute, 1 << 20, 80_660}, // 1 MiB / 13 s, rounded up
	} {
		if got := c.route.MinRate(c.n); got != c.want {
			t.Errorf("%s: MinRate(%d) = %d, want %d", c.name, c.n, got, c.want)
		}
	}
	if got := paceRate(1<<20, time.Second, 2*time.Second, MinBodyRate); got != MinBodyRate {
		t.Errorf("a timeout shorter than the grace: %d, want the floor", got)
	}
}

// TestPacer_Schedule: the k-th byte of a body is due grace + k/rate after the
// read began, and never after the route's read timeout, which still bounds a
// body whatever its length.
func TestPacer_Schedule(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	for _, n := range []int64{1, 50_000, 1_000_000, BigBody + 1, BigBodyRate * 118, 16 << 20} {
		rate := paceRate(n, BEEFReadTimeout, bodyread.ReadGrace, MinBodyRate)
		p := &pacer{start: start, end: start.Add(BEEFReadTimeout), grace: bodyread.ReadGrace, timeout: BEEFReadTimeout, floor: MinBodyRate, n: n}
		for _, have := range []int64{0, n / 4, n / 2, n - 1, n} {
			p.have = have
			want := start.Add(bodyread.ReadGrace + time.Duration(have)*time.Second/time.Duration(rate))
			if want.After(p.end) {
				want = p.end
			}
			if got := p.due(); !got.Equal(want) || got.After(p.end) {
				t.Errorf("n %d: byte %d due %v after the start, want %v, within %v", n, have, got.Sub(start), want.Sub(start), BEEFReadTimeout)
			}
		}
		p.have = n
		t.Logf("%d bytes at %d bytes a second: the last due %v after the start", n, rate, p.due().Sub(start))
	}
}

// sendAt writes n bytes to conn at rate bytes a second, as a link of that
// speed would: by any moment it has written what the rate allows by then, and
// a write held up by the scheduler is caught up.
func sendAt(conn net.Conn, n, rate int64, stop chan struct{}) {
	start := time.Now()
	for sent := int64(0); sent < n; {
		select {
		case <-stop:
			return
		case <-time.After(10 * time.Millisecond):
		}
		due := min(n, int64(time.Since(start).Seconds()*float64(rate)))
		if due > sent {
			if _, err := conn.Write(make([]byte, due-sent)); err != nil {
				return
			}
			sent = due
		}
	}
}

// slowUplink sends a body of n bytes at rate to a guard of the given grace
// and floor on a route with the given read timeout, and returns the result.
func slowUplink(t *testing.T, grace time.Duration, floor, n, rate int64, timeout time.Duration) bodyResult {
	t.Helper()
	g := New(4*n, 1, 1, testWait)
	g.grace, g.minRate = grace, floor
	srv, results := bodyServer(t, g, Route{MaxBody: 2 * n, Expansion: 1, ReadTimeout: timeout}, 0, 0)
	conn := rawPost(t, srv, int(n), nil)
	stop := make(chan struct{})
	defer close(stop)
	go sendAt(conn, n, rate, stop)
	return nextResult(t, results, timeout+5*time.Second)
}

// TestReadBody_HonestSlowUplinkPasses (cold review round 4 RISK 6): a 1 MB
// body sent at 200 kbit/s, 25,000 bytes a second, is read in full in about
// 40 s, where bodyread.MinReadRate cut it off. The test runs ten times
// faster: grace, floor, timeout and link all scaled by ten.
func TestReadBody_HonestSlowUplinkPasses(t *testing.T) {
	const scale, n, link = 10, 1_000_000, 25_000
	grace, timeout := bodyread.ReadGrace/scale, BEEFReadTimeout/scale
	res := slowUplink(t, grace, MinBodyRate*scale, n, link*scale, timeout)
	if res.err != nil || len(res.body) != n {
		t.Fatalf("1 MB at 200 kbit/s (scaled): %d bytes, %v after %v", len(res.body), res.err, res.elapsed)
	}
	t.Logf("1 MB at 200 kbit/s, ten times faster: read in %v (%v at full scale)", res.elapsed, res.elapsed*scale)
	old := slowUplink(t, grace, bodyread.MinReadRate*scale, n, link*scale, timeout)
	if !errors.Is(old.err, ErrBodyTooSlow) {
		t.Fatalf("the same body at bodyread.MinReadRate: %v after %v, want ErrBodyTooSlow", old.err, old.elapsed)
	}
	t.Logf("at bodyread.MinReadRate it was cut after %v (%v at full scale)", old.elapsed, old.elapsed*scale)
}

// TestReadBody_BigBodyKeepsBigBodyRate: a body over BigBody, which holds the
// one big-body slot, must keep BigBodyRate, so the slow uplink a 1 MB body
// passes on cuts it off, as bodyread.MinReadRate did. The test runs ten times
// faster, as TestReadBody_HonestSlowUplinkPasses does.
func TestReadBody_BigBodyKeepsBigBodyRate(t *testing.T) {
	const scale, n, link = 10, BigBody + 1, 25_000
	grace, timeout := bodyread.ReadGrace/scale, BEEFReadTimeout/scale
	res := slowUplink(t, grace, MinBodyRate*scale, n, link*scale, timeout)
	want := time.Duration(float64(grace) / (1 - float64(link)/float64(BigBodyRate)))
	if !errors.Is(res.err, ErrBodyTooSlow) || res.elapsed < grace || res.elapsed > 2*want {
		t.Fatalf("a body over BigBody at 200 kbit/s (scaled): %v after %v, want ErrBodyTooSlow at about %v", res.err, res.elapsed, want)
	}
	t.Logf("a body over BigBody at 200 kbit/s, ten times faster: cut after %v (expected about %v; %v at full scale)", res.elapsed, want, res.elapsed*scale)
}

// TestReadBody_LongBodyMustKeepItsTimeoutsPace: a body too long to arrive
// within its route's timeout at MinBodyRate must keep the pace that brings it
// in by the timeout. A trickle at four times the floor, which the floor alone
// would let hold the body's whole reservation until the timeout, is cut with
// ErrBodyTooSlow soon after the grace.
func TestReadBody_LongBodyMustKeepItsTimeoutsPace(t *testing.T) {
	const n = 1 << 20
	grace, timeout := 200*time.Millisecond, 2200*time.Millisecond // n/2 s is 512 KiB/s, 32 times the floor
	res := slowUplink(t, grace, MinBodyRate, n, 4*MinBodyRate, timeout)
	want := time.Duration(float64(grace) / (1 - float64(4*MinBodyRate)/float64(paceRate(n, timeout, grace, MinBodyRate))))
	if !errors.Is(res.err, ErrBodyTooSlow) || res.elapsed > timeout/2 {
		t.Fatalf("a 1 MiB body at 64 KiB/s with %v to arrive: %v after %v, want ErrBodyTooSlow at about %v", timeout, res.err, res.elapsed, want)
	}
	t.Logf("cut after %v (expected about %v), with %v of the timeout left", res.elapsed, want, timeout-res.elapsed)
}

// TestPacing_RealTime measures, at full scale and in real time, an honest
// 1 MB body at 200 kbit/s, the same at bodyread.MinReadRate, a body over
// BigBody at that link's rate, and two trickles. It takes about a minute, so
// it runs only with ANVIL_MEASURE_PACING=1.
func TestPacing_RealTime(t *testing.T) {
	if os.Getenv("ANVIL_MEASURE_PACING") != "1" {
		t.Skip("set ANVIL_MEASURE_PACING=1 to measure pacing in real time")
	}
	for _, c := range []struct {
		name        string
		floor, n    int64
		rate        int64
		wantTooSlow bool
	}{
		{"1 MB at 200 kbit/s", MinBodyRate, 1_000_000, 25_000, false},
		{"1 MB at 200 kbit/s, bodyread.MinReadRate", bodyread.MinReadRate, 1_000_000, 25_000, true},
		{"1 MiB + 1 byte at 200 kbit/s, over BigBody", MinBodyRate, BigBody + 1, 25_000, true},
		{"1 MB declared, trickled at 8 KiB/s", MinBodyRate, 1_000_000, 8 << 10, true},
		{"16 MiB declared, trickled at 64 KiB/s", MinBodyRate, 16 << 20, 64 << 10, true},
	} {
		res := slowUplink(t, bodyread.ReadGrace, c.floor, c.n, c.rate, BEEFReadTimeout)
		t.Logf("%s: %d bytes, %v, after %v (pace %d bytes a second)", c.name, len(res.body), res.err, res.elapsed, paceRate(c.n, BEEFReadTimeout, bodyread.ReadGrace, c.floor))
		if c.wantTooSlow != errors.Is(res.err, ErrBodyTooSlow) || (!c.wantTooSlow && res.err != nil) {
			t.Errorf("%s: %v, want too slow %v", c.name, res.err, c.wantTooSlow)
		}
	}
}

// TestPacerRate_UndeclaredFollowsBytesReadSoFar (cold review round 4 RISK 2):
// an undeclared body (n negative) is paced like a declared one of have
// bytes, recomputed as have grows, rather than like one of a fixed total —
// MinBodyRate while have is at most BigBody, then BigBodyRate, never the
// rate a body of MaxBody would need from its first byte.
func TestPacerRate_UndeclaredFollowsBytesReadSoFar(t *testing.T) {
	p := &pacer{timeout: BEEFReadTimeout, grace: bodyread.ReadGrace, floor: MinBodyRate, n: -1}
	for _, have := range []int64{0, 1000, BigBody, BigBody + 1, 16 << 20} {
		p.have = have
		want := paceRate(have, BEEFReadTimeout, bodyread.ReadGrace, MinBodyRate)
		if got := p.rate(); got != want {
			t.Errorf("undeclared, %d bytes read so far: rate %d, want %d (the schedule a declared body of %d bytes would keep)", have, got, want, have)
		}
	}
	// Early in the body, have is nowhere near MaxBEEFBody: pacing by have
	// must not demand the much faster rate a declared MaxBEEFBody submit
	// would (the regression this fixes).
	p.have = 150_000
	maxBodyRate := paceRate(MaxBEEFBody, BEEFReadTimeout, bodyread.ReadGrace, MinBodyRate)
	if got := p.rate(); got == maxBodyRate {
		t.Fatalf("an undeclared body that has read only %d of up to %d bytes was paced at MaxBody's rate %d", p.have, MaxBEEFBody, got)
	} else if got != MinBodyRate {
		t.Fatalf("an undeclared body that has read only %d bytes: rate %d, want the floor %d", p.have, got, MinBodyRate)
	}
}

// rawChunkedPost opens a connection to srv and sends the headers of a POST to
// /read with a chunked, undeclared body, leaving the connection open for the
// caller to write chunks on.
func rawChunkedPost(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprint(conn, "POST /read HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	return conn
}

// sendChunkedAt writes n bytes to conn as chunks of at most 4 KiB, at rate
// bytes a second, then the terminating zero-length chunk, as a link of that
// speed sending a chunked body would.
func sendChunkedAt(conn net.Conn, n, rate int64, stop chan struct{}) {
	const chunkSize = 4 << 10
	start := time.Now()
	for sent := int64(0); sent < n; {
		select {
		case <-stop:
			return
		case <-time.After(10 * time.Millisecond):
		}
		due := min(n, int64(time.Since(start).Seconds()*float64(rate)))
		for sent < due {
			k := min(chunkSize, due-sent)
			if _, err := fmt.Fprintf(conn, "%x\r\n", k); err != nil {
				return
			}
			if _, err := conn.Write(make([]byte, k)); err != nil {
				return
			}
			if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
				return
			}
			sent += k
		}
	}
	fmt.Fprint(conn, "0\r\n\r\n")
}

// trickleChunkedTo writes a chunk-encoded chunk of chunk bytes to conn every
// interval until stop closes or a write fails.
func trickleChunkedTo(conn net.Conn, chunk int, interval time.Duration, stop chan struct{}) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if _, err := fmt.Fprintf(conn, "%x\r\n", chunk); err != nil {
				return
			}
			if _, err := conn.Write(make([]byte, chunk)); err != nil {
				return
			}
			if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
				return
			}
		}
	}
}

// TestReadBody_UndeclaredHonestBodyPaces (cold review round 4 RISK 2): a 150
// KB chunked BEEF sent at 200 kbit/s passes, as it did before this guard
// existed (base e63349f); paced at the rate a declared MaxBody submit would
// need (142,180 B/s), it was cut at 2.43 s instead.
func TestReadBody_UndeclaredHonestBodyPaces(t *testing.T) {
	const n, link = 150_000, 25_000                      // 200 kbit/s
	g := New(MemoryBudget-ExecAllowance, 1, 1, testWait) // room for an undeclared body's MaxBody-sized reservation
	srv, results := bodyServer(t, g, BEEFRoute, 0, 0)
	conn := rawChunkedPost(t, srv)
	stop := make(chan struct{})
	defer close(stop)
	go sendChunkedAt(conn, n, link, stop)
	res := nextResult(t, results, 15*time.Second)
	if res.err != nil || len(res.body) != n {
		t.Fatalf("a 150 KB chunked BEEF at 200 kbit/s: %d bytes, %v after %v, want it to pass", len(res.body), res.err, res.elapsed)
	}
	if want := time.Duration(n) * time.Second / time.Duration(link); res.elapsed < want {
		t.Fatalf("read in %v, faster than the 200 kbit/s link allows (%v): the test proves nothing", res.elapsed, want)
	}
	t.Logf("150 KB chunked BEEF at 200 kbit/s: read in %v", res.elapsed)
}

// TestReadBody_UndeclaredTrickleIsStillCut (cold review round 4 RISK 2): an
// undeclared body is still paced, not exempted: one trickling at an eighth
// of MinBodyRate is cut with ErrBodyTooSlow soon after the grace, as a
// declared one is (TestReadBody_TrickleBelowTheRateIsCut).
func TestReadBody_UndeclaredTrickleIsStillCut(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	route := Route{MaxBody: 1 << 20, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawChunkedPost(t, srv)
	stop := make(chan struct{})
	defer close(stop)
	go trickleChunkedTo(conn, int(MinBodyRate/80), 100*time.Millisecond, stop) // 1/8 of the floor
	res := nextResult(t, results, route.ReadTimeout)
	want := bodyread.ReadGrace * 8 / 7
	if !errors.Is(res.err, ErrBodyTooSlow) {
		t.Fatalf("an undeclared trickle at an eighth of the floor: %v after %v, want ErrBodyTooSlow", res.err, res.elapsed)
	}
	if res.elapsed < bodyread.ReadGrace || res.elapsed > want+time.Second {
		t.Fatalf("the undeclared trickle was cut after %v, want about %v", res.elapsed, want)
	}
}
