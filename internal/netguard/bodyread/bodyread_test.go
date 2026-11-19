package bodyread

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// trickle is a body that delivers chunk bytes every interval until it has
// delivered total, then io.EOF; a negative total never ends. A Read waiting
// for its next chunk returns at once once the body is closed. It counts its
// Close calls and its Read calls.
type trickle struct {
	chunk    int
	interval time.Duration
	total    int
	sent     int
	reads    atomic.Int64
	closes   atomic.Int64
	closed   chan struct{}
}

func newTrickle(chunk int, interval time.Duration, total int) *trickle {
	return &trickle{chunk: chunk, interval: interval, total: total, closed: make(chan struct{})}
}

func (b *trickle) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.total >= 0 && b.sent >= b.total {
		return 0, io.EOF
	}
	select {
	case <-b.closed:
		return 0, errors.New("read on a closed body")
	case <-time.After(b.interval):
	}
	n := min(len(p), b.chunk)
	if b.total >= 0 {
		n = min(n, b.total-b.sent)
	}
	for i := range n {
		p[i] = 'a'
	}
	b.sent += n
	return n, nil
}

func (b *trickle) Close() error {
	if b.closes.Add(1) == 1 {
		close(b.closed)
	}
	return nil
}

// readWithin runs Read and fails the test if it has not returned within
// limit, so a missing deadline fails rather than hangs.
func readWithin(t *testing.T, limit time.Duration, body io.ReadCloser, n int64, l Limits) ([]byte, error, time.Duration) {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	start := time.Now()
	done := make(chan result, 1)
	go func() {
		b, err := Read(body, n, l)
		done <- result{b, err}
	}()
	select {
	case r := <-done:
		return r.b, r.err, time.Since(start)
	case <-time.After(limit):
		_ = body.Close()
		t.Fatalf("Read did not return within %v", limit)
		return nil, nil, 0
	}
}

// TestPermits_BoundReadsInProgress: only n permits are out at once; a wait
// for another gives up when its context ends, with ErrNoPermit wrapping the
// cause; release returns a permit once however often it is called.
func TestPermits_BoundReadsInProgress(t *testing.T) {
	p := NewPermits(2)
	first, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(ctx); !errors.Is(err, ErrNoPermit) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a third permit: want ErrNoPermit wrapping the deadline, got %v", err)
	}
	first()
	first()
	if got := p.InUse(); got != 1 {
		t.Fatalf("after releasing one permit twice, %d are in use, want 1", got)
	}
	third, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("a freed permit must be taken again: %v", err)
	}
	second()
	third()
	if got := p.InUse(); got != 0 {
		t.Fatalf("%d permits in use after all were released", got)
	}
}

// TestPermits_NeverGoToAnEndedContext: Acquire on a context that has already
// ended fails with ErrNoPermit even while permits are free, so a read whose
// request is over never starts. A select alone would take a free permit about
// half the time, so 200 attempts all failing rules that out.
func TestPermits_NeverGoToAnEndedContext(t *testing.T) {
	p := NewPermits(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 200 {
		release, err := p.Acquire(ctx)
		if err == nil {
			release()
			t.Fatalf("attempt %d: an ended context was given a free permit", i)
		}
		if !errors.Is(err, ErrNoPermit) || !errors.Is(err, context.Canceled) {
			t.Fatalf("want ErrNoPermit wrapping the cancellation, got %v", err)
		}
	}
	if got := p.InUse(); got != 0 {
		t.Fatalf("%d permits in use after only refusals", got)
	}
}

// TestRead_HoldsBodiesToTheirCap: a body of exactly Max bytes reads in full,
// declared or streamed; one byte more fails with ErrTooLarge, and a declared
// length over Max fails before the body is read at all. The body is closed
// once on every path, and a streamed body grows its buffer no further than
// one byte past the cap.
func TestRead_HoldsBodiesToTheirCap(t *testing.T) {
	const capBytes = 100 << 10
	for _, tc := range []struct {
		name     string
		size     int
		declared bool
		want     error
	}{
		{"declared at the cap", capBytes, true, nil},
		{"streamed at the cap", capBytes, false, nil},
		{"declared over the cap", capBytes + 1, true, ErrTooLarge},
		{"streamed over the cap", capBytes + 1, false, ErrTooLarge},
		{"empty", 0, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := newTrickle(64<<10, 0, tc.size)
			n := int64(-1)
			if tc.declared {
				n = int64(tc.size)
			}
			got, err, _ := readWithin(t, 5*time.Second, body, n, Limits{Max: capBytes})
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.want == nil && (len(got) != tc.size || !bytes.Equal(got, bytes.Repeat([]byte{'a'}, tc.size))) {
				t.Fatalf("read %d bytes, want %d", len(got), tc.size)
			}
			if tc.want == nil && cap(got) > capBytes+1 {
				t.Fatalf("the buffer grew to %d bytes, past the cap", cap(got))
			}
			if tc.declared && tc.want != nil && body.reads.Load() != 0 {
				t.Fatalf("a declared length over the cap was read %d times", body.reads.Load())
			}
			if c := body.closes.Load(); c != 1 {
				t.Fatalf("the body was closed %d times, want once", c)
			}
		})
	}
}

// TestRead_TimeoutCutsAStalledBody: a body that stalls is cut off at the
// timeout, closed once, with ErrTimeout.
func TestRead_TimeoutCutsAStalledBody(t *testing.T) {
	for _, n := range []int64{1000, -1} {
		body := newTrickle(1, time.Hour, -1)
		_, err, took := readWithin(t, 5*time.Second, body, n, Limits{Max: 1 << 20, Timeout: 50 * time.Millisecond})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("length %d: want ErrTimeout, got %v", n, err)
		}
		if took > time.Second {
			t.Fatalf("length %d: the 50ms timeout took %v", n, took)
		}
		if c := body.closes.Load(); c != 1 {
			t.Fatalf("length %d: the body was closed %d times, want once", n, c)
		}
	}
}

// TestRead_MinRateCutsATrickle: once Grace has passed, a body must keep up
// MinRate on average. One trickling at a quarter of the rate is cut off with
// ErrTooSlow about Grace + n/MinRate after the read began, well before its
// timeout; one at four times the rate reads in full.
func TestRead_MinRateCutsATrickle(t *testing.T) {
	l := Limits{Max: 1 << 20, Timeout: 10 * time.Second, Grace: 100 * time.Millisecond, MinRate: 4000}

	slow := newTrickle(100, 100*time.Millisecond, 40_000) // 1,000 bytes/s
	_, err, took := readWithin(t, 15*time.Second, slow, 40_000, l)
	if !errors.Is(err, ErrTooSlow) {
		t.Fatalf("a trickle at a quarter of the rate: want ErrTooSlow, got %v after %v", err, took)
	}
	// With n bytes in by time t, the cut comes at Grace + n/MinRate, and at
	// 1,000 bytes/s n is about t x 1,000: t = 0.1 s + t/4, about 133 ms.
	if took < 100*time.Millisecond || took > 2*time.Second {
		t.Fatalf("the trickle was cut after %v, want about 133ms", took)
	}
	if c := slow.closes.Load(); c != 1 {
		t.Fatalf("the slow body was closed %d times, want once", c)
	}

	fast := newTrickle(400, 25*time.Millisecond, 8_000) // 16,000 bytes/s for 0.5 s
	got, err, _ := readWithin(t, 15*time.Second, fast, -1, l)
	if err != nil || len(got) != 8_000 {
		t.Fatalf("a body at four times the rate must read in full: %d bytes, %v", len(got), err)
	}
}

// TestRead_PassesOtherReadErrors: a read error that no limit caused comes
// back as it is, and a body that ends short of its declared length is an
// unexpected EOF.
func TestRead_PassesOtherReadErrors(t *testing.T) {
	broken := errors.New("connection reset")
	_, err := Read(io.NopCloser(io.MultiReader(strings.NewReader("ab"), errReader{broken})), -1, Limits{Max: 10})
	if !errors.Is(err, broken) {
		t.Fatalf("want the read error, got %v", err)
	}
	_, err = Read(io.NopCloser(strings.NewReader("ab")), 5, Limits{Max: 10})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF for a short body, got %v", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// blockingBody declares a length but never delivers a byte, blocking until
// closed, so a test can measure what a declared Content-Length alone costs
// before any byte of the body has arrived.
type blockingBody struct{ closed chan struct{} }

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("read on a closed body")
}

func (b *blockingBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

// TestReadKnown_DoesNotPreallocateTheDeclaredLength: a declared length of 64
// MiB -- netguard's own cap on a GASP node reply -- from a body that never
// sends a byte, cut short at its timeout, costs the process nowhere near 64
// MiB of heap. Before this fix, readKnown allocated the full declared
// length up front (make([]byte, n)), so a peer could make this cost real
// heap for every reply it merely declared and never had to send (cold
// review round 4 cycle 6, RISK 1).
func TestReadKnown_DoesNotPreallocateTheDeclaredLength(t *testing.T) {
	const declared = 64 << 20
	body := &blockingBody{closed: make(chan struct{})}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	_, err := Read(body, declared, Limits{Max: declared, Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapInuse) - int64(before.HeapInuse)
	const tooMuch = 8 << 20 // far under the 64 MiB declared, generous over any small initial buffer
	if grew > tooMuch {
		t.Fatalf("heap grew by %d bytes for a body that sent nothing of its declared %d bytes, want under %d", grew, declared, tooMuch)
	}
}
