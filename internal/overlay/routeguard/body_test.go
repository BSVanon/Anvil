package routeguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bodyResult is what a test handler saw of ReadBody.
type bodyResult struct {
	body    []byte
	err     error
	elapsed time.Duration
	held    int64 // the ticket's reservation once the body was read
}

// bodyServer serves POST /read through ReadBody for route on g, reporting
// each result on the returned channel after lingering for linger, and GET
// /stream, which writes a line every 100 ms until its request context ends or
// it has written n lines.
func bodyServer(t *testing.T, g *Guard, route Route, n int, linger time.Duration) (*httptest.Server, chan bodyResult) {
	t.Helper()
	results := make(chan bodyResult, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /read", func(w http.ResponseWriter, r *http.Request) {
		tk, _ := g.Begin(false)
		defer tk.Close()
		start := time.Now()
		body, err := tk.ReadBody(w, r, route)
		res := bodyResult{body: body, err: err, elapsed: time.Since(start), held: tk.Reserved()}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			results <- res
			return
		}
		// Outlive the read timeout: the cleared deadline must not cut the
		// rest of the exchange or cancel the request.
		select {
		case <-time.After(linger):
			fmt.Fprint(w, "ok")
		case <-r.Context().Done():
			res.err = r.Context().Err()
		}
		results <- res
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < n; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			fmt.Fprintf(w, "line %d\n", i)
			w.(http.Flusher).Flush()
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, results
}

// TestReadBody_SlowSenderIsCutAtTheDeadline: a sender that declares a body
// and trickles it is cut off at the route's read timeout, with
// ErrReadTimeout, and what it held is returned.
func TestReadBody_SlowSenderIsCutAtTheDeadline(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	route := Route{MaxBody: 1 << 20, Expansion: 4, ReadTimeout: 300 * time.Millisecond}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n")
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				if _, err := conn.Write([]byte{'x'}); err != nil {
					return
				}
			}
		}
	}()
	select {
	case res := <-results:
		if !errors.Is(res.err, ErrReadTimeout) {
			t.Fatalf("ReadBody of a trickled body: %v, want ErrReadTimeout", res.err)
		}
		if res.elapsed < route.ReadTimeout || res.elapsed > route.ReadTimeout+time.Second {
			t.Fatalf("cut after %v, want about %v", res.elapsed, route.ReadTimeout)
		}
		t.Logf("trickling sender cut after %v, holding %d bytes", res.elapsed, res.held)
	case <-time.After(5 * time.Second):
		t.Fatal("a trickling sender was not cut off within 5 s")
	}
	tk, _ := g.Begin(false)
	defer tk.Close()
	if err := tk.Reserve(t.Context(), 1<<20); err != nil {
		t.Fatalf("the cut request's reservation was not returned: %v", err)
	}
}

// TestReadBody_DeadlineIsClearedOnceTheBodyIsIn: after ReadBody, the handler
// may run past the read timeout without its request being cancelled, and the
// next request on the same connection, a stream longer than the timeout, runs
// to its end, whether the body was declared or chunked (read to its end,
// after which the server watches the connection for the client going away).
// go1.26's server clears a connection's read deadline itself when it starts
// that watch and when it reads the next request, so these pass without
// ReadBody's own clear too; the clear stands for servers that do not.
func TestReadBody_DeadlineIsClearedOnceTheBodyIsIn(t *testing.T) {
	for name, request := range map[string]string{
		"declared": "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
		"chunked":  "POST /read HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	} {
		g := New(1<<20, 1, 1, testWait)
		route := Route{MaxBody: 1 << 20, Expansion: 1, ReadTimeout: 200 * time.Millisecond}
		const lines = 6
		srv, results := bodyServer(t, g, route, lines, 2*route.ReadTimeout)
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		fmt.Fprint(conn, request)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		res := <-results
		if res.err != nil || string(got) != "ok" {
			t.Fatalf("%s: handler outliving the read timeout: err %v, reply %q", name, res.err, got)
		}
		start := time.Now()
		fmt.Fprintf(conn, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
		resp, err = http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		streamed, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if n := strings.Count(string(streamed), "\n"); n != lines {
			t.Fatalf("%s: the stream on the same connection wrote %d of %d lines in %v", name, n, lines, time.Since(start))
		}
	}
}

// TestReadBody_ReservesBeforeReading: a body whose reservation cannot be met
// is refused, ErrBusy at the guard's Wait, before its first byte is read, so
// a client that waits for 100 Continue never sends it.
func TestReadBody_ReservesBeforeReading(t *testing.T) {
	g := New(3000, 1, 1, testWait)
	holder, _ := g.Begin(false)
	_ = holder.Reserve(t.Context(), 2000)
	defer holder.Close()
	route := Route{MaxBody: 1 << 20, Expansion: 10, ReadTimeout: 5 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	counter := &countingReader{r: bytes.NewReader(make([]byte, 200))}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/read", counter)
	req.ContentLength = 200
	req.Header.Set("Expect", "100-continue")
	client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 10 * time.Second}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res := <-results
	if !errors.Is(res.err, ErrBusy) {
		t.Fatalf("ReadBody over the free heap: %v, want ErrBusy", res.err)
	}
	if counter.n != 0 {
		t.Fatalf("the client sent %d body bytes the guard refused to read", counter.n)
	}
}

// TestReadBody_UnknownLengthReservesTheCapThenShrinks: a chunked body
// reserves for MaxBody before its first byte is read, so one that cannot have
// that much is refused unread, and once it is in it holds only what its
// length needs.
func TestReadBody_UnknownLengthReservesTheCapThenShrinks(t *testing.T) {
	route := Route{MaxBody: 64 << 10, Expansion: 4, Allowance: 100, ReadTimeout: 5 * time.Second}
	g := New(route.Allowance+4*route.MaxBody, 1, 1, testWait)
	srv, results := bodyServer(t, g, route, 0, 0)
	post := func(n int) (bodyResult, int) {
		counter := &countingReader{r: bytes.NewReader(make([]byte, n))}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/read", io.NopCloser(counter))
		req.ContentLength = -1
		req.Header.Set("Expect", "100-continue")
		client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 10 * time.Second}}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return <-results, counter.n
	}
	res, _ := post(1000)
	if res.err != nil || len(res.body) != 1000 {
		t.Fatalf("a chunked body within the budget: %d bytes, %v", len(res.body), res.err)
	}
	if want := route.Allowance + 4*1000; res.held != want {
		t.Fatalf("held %d bytes for a 1000-byte chunked body, want %d", res.held, want)
	}
	holder, _ := g.Begin(false)
	defer holder.Close()
	if err := holder.Reserve(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	res, sent := post(1000)
	if !errors.Is(res.err, ErrBusy) {
		t.Fatalf("a chunked body that cannot reserve for the cap: %v, want ErrBusy", res.err)
	}
	if sent != 0 {
		t.Fatalf("the client sent %d body bytes the guard refused to read", sent)
	}
}

// TestReadBody_OneBigBodyAtATime: a body over BigBody takes the one big-body
// slot before it reserves, so a second waits the guard's Wait and is refused
// while a small one goes ahead; the slot is free again once the first ends.
func TestReadBody_OneBigBodyAtATime(t *testing.T) {
	g := New(1<<30, 1, 1, testWait)
	route := Route{MaxBody: 4 * BigBody, Expansion: 1, ReadTimeout: 5 * time.Second}
	first, _ := g.Begin(false)
	if err := first.take(t.Context(), slotBig); err != nil {
		t.Fatal(err)
	}
	srv, results := bodyServer(t, g, route, 0, 0)
	post := func(n int) bodyResult {
		resp, err := http.Post(srv.URL+"/read", "application/octet-stream", bytes.NewReader(make([]byte, n)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return <-results
	}
	start := time.Now()
	if res := post(int(BigBody) + 1); !errors.Is(res.err, ErrBusy) {
		t.Fatalf("a second big body: %v, want ErrBusy", res.err)
	}
	if waited := time.Since(start); waited < testWait {
		t.Fatalf("refused after %v, before the guard's Wait of %v", waited, testWait)
	}
	if res := post(int(BigBody)); res.err != nil {
		t.Fatalf("a body of BigBody bytes while the big-body slot is taken: %v", res.err)
	}
	first.Close()
	if res := post(int(BigBody) + 1); res.err != nil {
		t.Fatalf("a big body after the slot was returned: %v", res.err)
	}
}

// TestRoute_BEEFReservation: a BEEF route reserves, beyond its expansion, the
// most its parse and its scripts' verification can hold for a body that long,
// and no more than the pool for a body at the cap.
func TestRoute_BEEFReservation(t *testing.T) {
	r := Route{Expansion: 12, BEEF: true}
	for _, c := range []struct{ n, total, headroom int64 }{
		{100, 1200 + 50*100 + 64<<10 + 896*100, 896 * 100},
		{1 << 20, 12<<20 + 32<<20 + 896*MaxScriptOps, 896 * MaxScriptOps},
	} {
		total, headroom := r.Reservation(c.n)
		if total != c.total || headroom != c.headroom {
			t.Errorf("reservation(%d) = %d, %d; want %d, %d", c.n, total, headroom, c.total, c.headroom)
		}
	}
	if total, _ := BEEFRoute.Reservation(MaxBEEFBody); total > MemoryBudget-ExecAllowance {
		t.Fatalf("a submit at the cap reserves %d bytes, more than the %d pool", total, MemoryBudget-ExecAllowance)
	}
}

// TestReadBody_OverTheCapIsRefusedUnread: a declared length over MaxBody is
// refused before any reservation or read; a chunked body over it fails with
// the same error once it passes the cap.
func TestReadBody_OverTheCapIsRefusedUnread(t *testing.T) {
	g := New(1<<30, 1, 1, testWait)
	route := Route{MaxBody: 1000, Expansion: 1, ReadTimeout: 5 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	for _, chunked := range []bool{false, true} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/read", io.NopCloser(bytes.NewReader(make([]byte, 1001))))
		req.ContentLength = 1001
		if chunked {
			req.ContentLength = -1
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		res := <-results
		var tooLarge *http.MaxBytesError
		if !errors.As(res.err, &tooLarge) {
			t.Fatalf("chunked=%v: %v, want *http.MaxBytesError", chunked, res.err)
		}
		if !chunked && res.held != 0 {
			t.Fatalf("a declared over-cap body reserved %d bytes", res.held)
		}
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
