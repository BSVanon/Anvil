package netguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// shortGuard is a guard whose /submit exchanges last at most timeout, with
// no rate floor, so each test sees one limit at work.
func shortGuard(timeout time.Duration) *guard {
	return &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, maxSteakBytes: MaxSteakBytes, submitTimeout: timeout}
}

// submitRequest is a POST to url+path as go-sdk's facilitator builds it.
func submitRequest(t *testing.T, ctx context.Context, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/submit", bytes.NewBuffer([]byte("beef")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["tm_test"]`)
	return req
}

// TestGuard_SubmitExchangeHasOneDeadline: one /submit exchange, from sending
// the request to the reply's last byte and across every redirect, ends at
// the guard's submit timeout: a host that stalls before its headers, one that
// trickles its body, and one whose three redirect hops each fit the timeout
// but together do not. go-sdk's facilitator gives each send 30 s on a context
// of its own, and the guard's deadline still ends it.
func TestGuard_SubmitExchangeHasOneDeadline(t *testing.T) {
	const timeout = 400 * time.Millisecond
	stop := make(chan struct{})
	wait := func(r *http.Request, d time.Duration) bool {
		select {
		case <-time.After(d):
			return true
		case <-r.Context().Done():
		case <-stop:
		}
		return false
	}
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		wait(r, time.Minute)
	}))
	trickle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tm_test":{"outputsToAdmit":[`))
		for wait(r, 20*time.Millisecond) {
			if _, err := w.Write([]byte(" ")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	var hops atomic.Int64
	redirects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if !wait(r, 250*time.Millisecond) {
			return
		}
		switch r.URL.Path {
		case "/submit":
			http.Redirect(w, r, "/second", http.StatusTemporaryRedirect)
		case "/second":
			http.Redirect(w, r, "/third", http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	for _, srv := range []*httptest.Server{stall, trickle, redirects} {
		t.Cleanup(srv.Close)
	}
	t.Cleanup(func() { close(stop) }) // runs first, so the servers do not wait on their handlers

	client := &http.Client{Transport: shortGuard(timeout)}
	for name, url := range map[string]string{
		"stalls before its headers": stall.URL,
		"trickles its body":         trickle.URL,
		"redirects three times":     redirects.URL,
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			resp, err := client.Do(submitRequest(t, context.Background(), url))
			took := time.Since(start)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("the exchange must end at the %v timeout, it succeeded after %v", timeout, took)
			}
			if took < timeout-50*time.Millisecond || took > timeout+time.Second {
				t.Fatalf("the exchange ended after %v (%v), want about %v", took, err, timeout)
			}
		})
	}
	if n := hops.Load(); n != 2 {
		t.Fatalf("the redirected exchange reached %d hops by its deadline, want 2", n)
	}

	start := time.Now()
	_, err := (&topic.HTTPSOverlayBroadcastFacilitator{Client: client}).Send(trickle.URL,
		&overlay.TaggedBEEF{Beef: []byte("beef"), Topics: []string{"tm_test"}})
	if took := time.Since(start); err == nil || took > timeout+time.Second {
		t.Fatalf("go-sdk's facilitator must give up at the guard's %v timeout, took %v: %v", timeout, took, err)
	}
}

// endlessBody delivers a space every 20 ms until it is closed, whatever
// happens to the context of the request it answers.
type endlessBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *endlessBody) Read(p []byte) (int, error) {
	select {
	case <-b.closed:
		return 0, errors.New("read on a closed body")
	case <-time.After(20 * time.Millisecond):
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = ' '
	return 1, nil
}

func (b *endlessBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestGuard_SubmitReadTimeoutHoldsWithoutTheContext: the guard reads a STEAK
// under a timeout of its own, the time left in the exchange, so a reply whose
// body ignores the request's context, as a base transport other than
// net/http's may hand on, still cannot hold the read open.
func TestGuard_SubmitReadTimeoutHoldsWithoutTheContext(t *testing.T) {
	const timeout = 400 * time.Millisecond
	g := shortGuard(timeout)
	g.base = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, ContentLength: -1,
			Body: &endlessBody{closed: make(chan struct{})}}, nil
	})
	req := submitRequest(t, context.Background(), "http://peer.invalid")
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{Transport: g}).Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "/submit reply not read within the 400ms exchange timeout") {
			t.Fatalf("want the read cut at the exchange timeout, got %v", err)
		}
		if took := time.Since(start); took > timeout+time.Second {
			t.Fatalf("the read took %v, want about %v", took, timeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read outlived the exchange timeout by seconds")
	}
}

// TestGuard_ValidatesSteaksBehindRedirects: a host can answer the submit POST
// with a redirect, which the client follows, so the guard judges the final
// reply by the request that began the exchange.
func TestGuard_ValidatesSteaksBehindRedirects(t *testing.T) {
	for _, code := range []int{http.StatusSeeOther, http.StatusTemporaryRedirect} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if r.URL.Path == "/submit" {
				http.Redirect(w, r, "/elsewhere", code)
				return
			}
			_, _ = w.Write([]byte(`null`))
		}))
		t.Cleanup(srv.Close)
		_, err := noPanicValue(t, "facilitator", func() (*overlay.Steak, error) {
			return (&topic.HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}).Send(srv.URL,
				&overlay.TaggedBEEF{Beef: []byte("beef"), Topics: []string{"tm_test"}})
		})
		if !errors.Is(err, ErrInvalidSteak) || !strings.Contains(err.Error(), "the reply is null") {
			t.Fatalf("redirect %d: expected the redirected reply to be refused, got: %v", code, err)
		}
	}
}

// TestGuard_HandsOnOnlyTheTopicsTheRequestNamed: go-sdk's Broadcaster reads
// every topic of a STEAK and dereferences each (topic/broadcaster.go:178), so
// a null under a topic the request never named panics it as surely as one
// under a named topic. The guard hands on the STEAK re-encoded from what it
// validated, the named topics only, and the Broadcaster takes the
// acknowledgement; on an unguarded client the same reply panics it.
func TestGuard_HandsOnOnlyTheTopicsTheRequestNamed(t *testing.T) {
	reply := hostiletest.Literal("unrequested", []byte(`{"tm_test":{"outputsToAdmit":[0]},"tm_unrequested":null}`))
	url, _ := steakHost(t, reply, false)
	tx := broadcastTx(t)
	beef, err := tx.AtomicBEEF(false)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	got, err := (&topic.HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}).Send(url,
		&overlay.TaggedBEEF{Beef: beef, Topics: []string{testTopic}})
	if err != nil || len(*got) != 1 || (*got)[testTopic] == nil {
		t.Fatalf("want the STEAK for %s alone, got %s, %v", testTopic, dumpPtr(got), err)
	}

	ship := shipHostFor(t, []string{url})
	success, failure := noPanicValue(t, "Broadcaster", func() (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
		return stockBroadcaster(t, ship, nil).BroadcastCtx(context.Background(), tx)
	})
	if failure != nil || success == nil {
		t.Fatalf("the Broadcaster must take the acknowledgement for %s, got %+v", testTopic, failure)
	}
	unguarded := &topic.HTTPSOverlayBroadcastFacilitator{Client: &http.Client{}}
	if !panics(func() { stockBroadcaster(t, ship, unguarded).BroadcastCtx(context.Background(), tx) }) {
		t.Fatal("on an unguarded client this reply must panic go-sdk's Broadcaster, or the case tests nothing")
	}
}

// TestGuard_PassesOtherSubmitRepliesCapped: a reply other than 200 reaches
// the caller as it came, capped at MaxSteakBytes, and closing it ends the
// exchange; one declaring more than the cap is refused outright.
func TestGuard_PassesOtherSubmitRepliesCapped(t *testing.T) {
	envelope := []byte(`{"status":"error","message":"no topics specified"}`)
	big := bytes.Repeat([]byte("x"), int(MaxSteakBytes)+1)
	var exchange context.Context
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Query().Get("reply") {
		case "envelope":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(envelope)
		case "streamed":
			w.WriteHeader(http.StatusInternalServerError)
			w.(http.Flusher).Flush()
			_, _ = w.Write(big)
		default:
			w.Header().Set("Content-Length", "2000000")
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	g := &guard{base: ctxRecorder{rt: http.DefaultTransport, ctx: &exchange}, maxBytes: MaxResponseBytes}
	client := &http.Client{Transport: g}
	post := func(reply string) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/submit?reply="+reply, bytes.NewReader([]byte("{}")))
		return client.Do(req)
	}

	resp, err := post("envelope")
	if err != nil {
		t.Fatalf("an error reply must reach the caller: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusBadRequest || !bytes.Equal(got, envelope) {
		t.Fatalf("error reply changed: %d %q %v", resp.StatusCode, got, err)
	}
	if exchange.Err() != nil {
		t.Fatal("the exchange ended before its body was closed")
	}
	_ = resp.Body.Close()
	if exchange.Err() == nil {
		t.Fatal("closing the reply must end the exchange")
	}

	resp, err = post("streamed")
	if err != nil {
		t.Fatalf("a streamed error reply must reach the caller: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if !errors.Is(err, ErrResponseTooLarge) || n != MaxSteakBytes {
		t.Fatalf("want ErrResponseTooLarge after %d bytes, read %d, err %v", MaxSteakBytes, n, err)
	}

	if resp, err = post("declared"); err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrResponseTooLarge) || !strings.Contains(err.Error(), "/submit reply Content-Length 2000000 is over 1048576 bytes") {
		t.Fatalf("want the declared length refused, got: %v", err)
	}
}

// ctxRecorder is a transport that records the context of the last request
// it sent.
type ctxRecorder struct {
	rt  http.RoundTripper
	ctx *context.Context
}

func (c ctxRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	*c.ctx = req.Context()
	return c.rt.RoundTrip(req)
}

// TestIsSubmit: submits are recognized however the facilitator's
// host + "/submit" parses, by X-Topics, and by the request that started a
// redirected exchange; lookups and everything else are not.
func TestIsSubmit(t *testing.T) {
	post := func(url string) *http.Request { return newRequest(t, http.MethodPost, url) }
	topics := post("http://h/anything")
	topics.Header.Set("X-Topics", `["tm_a"]`)
	redirected := newRequest(t, http.MethodGet, "http://h/elsewhere")
	redirected.Response = &http.Response{Request: post("http://h/submit")}
	redirectedLookup := newRequest(t, http.MethodGet, "http://h/submit")
	redirectedLookup.Response = &http.Response{Request: post("http://h/lookup")}
	aggregated := post("http://h/submit")
	aggregated.Header.Set("X-Aggregation", "yes")

	for name, tc := range map[string]struct {
		req  *http.Request
		want bool
	}{
		"POST /submit":                   {post("http://h/submit"), true},
		"POST under a path":              {post("http://h/api/overlay/submit"), true},
		"submit in the query string":     {post("http://h/x?/submit"), true},
		"submit in the fragment":         {post("http://h/x#/submit"), true},
		"X-Topics header":                {topics, true},
		"redirect follow-up of a submit": {redirected, true},
		"redirect follow-up of a lookup": {redirectedLookup, false},
		"marked as a lookup":             {aggregated, false},
		"GET /submit":                    {newRequest(t, http.MethodGet, "http://h/submit"), false},
		"POST /lookup":                   {post("http://h/lookup"), false},
		"POST /submits":                  {post("http://h/submits"), false},
	} {
		if got := isSubmit(tc.req); got != tc.want {
			t.Errorf("%s: isSubmit = %v, want %v", name, got, tc.want)
		}
	}
}
