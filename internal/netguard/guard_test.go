package netguard

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// fakeTransport answers every request with one canned response.
type fakeTransport struct{ resp *http.Response }

func (f fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.resp.Request = req
	return f.resp, nil
}

// trackedBody is a response body that records whether it was closed.
type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func newRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, url, err)
	}
	return req
}

// TestInstall_GuardsTheExistingClientOnce: Install changes the
// http.DefaultClient object itself, so a pointer captured before it ran is
// guarded too; a second Install does not wrap again; http.DefaultTransport,
// which other clients use, stays as it was.
func TestInstall_GuardsTheExistingClientOnce(t *testing.T) {
	g, ok := http.DefaultClient.Transport.(*guard)
	if !ok {
		t.Fatalf("http.DefaultClient.Transport is %T, want *guard", http.DefaultClient.Transport)
	}
	if capturedBeforeInstall != http.DefaultClient {
		t.Fatal("Install must change the existing client, not replace http.DefaultClient")
	}
	Install()
	if http.DefaultClient.Transport != g {
		t.Fatal("a second Install must not wrap the transport again")
	}
	if g.base != http.DefaultTransport || g.maxBytes != MaxResponseBytes || g.maxLookupBytes != peerhygiene.MaxLookupResponseBytes ||
		g.readTimeout != peerhygiene.LookupReadTimeout {
		t.Fatalf("guard misconfigured: base %T, maxBytes %d, maxLookupBytes %d, readTimeout %v",
			g.base, g.maxBytes, g.maxLookupBytes, g.readTimeout)
	}
	if g.minRate != bodyread.MinReadRate || g.grace != bodyread.ReadGrace || g.maxSteakBytes != MaxSteakBytes ||
		g.submitTimeout != SubmitTimeout {
		t.Fatalf("guard misconfigured: minRate %d, grace %v, maxSteakBytes %d, submitTimeout %v",
			g.minRate, g.grace, g.maxSteakBytes, g.submitTimeout)
	}
	if _, ok := http.DefaultTransport.(*http.Transport); !ok {
		t.Fatalf("http.DefaultTransport must stay unwrapped, got %T", http.DefaultTransport)
	}
}

// streamServer serves n bytes, streamed in 1 MiB writes with no
// Content-Length.
func streamServer(t *testing.T, n int64) string {
	t.Helper()
	chunk := bytes.Repeat([]byte{'a'}, 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for left := n; left > 0; {
			k := min(left, int64(len(chunk)))
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			left -= k
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestInstall_CapsStreamedBodies: through http.DefaultClient (here via
// http.Get), a body of exactly MaxResponseBytes reads in full, and one byte
// more fails with ErrResponseTooLarge after exactly MaxResponseBytes, every
// read after that failing too.
func TestInstall_CapsStreamedBodies(t *testing.T) {
	resp, err := http.Get(streamServer(t, MaxResponseBytes))
	if err != nil {
		t.Fatalf("GET at the cap: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil || n != MaxResponseBytes {
		t.Fatalf("a body at the cap must read in full: read %d bytes, err %v", n, err)
	}

	resp, err = http.Get(streamServer(t, MaxResponseBytes+1))
	if err != nil {
		t.Fatalf("GET over the cap: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, err = io.Copy(io.Discard, resp.Body)
	if !errors.Is(err, ErrResponseTooLarge) || n != MaxResponseBytes {
		t.Fatalf("expected ErrResponseTooLarge after %d bytes, read %d bytes, err %v", MaxResponseBytes, n, err)
	}
	if _, err := resp.Body.Read(make([]byte, 1)); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("the cap error must be sticky, got: %v", err)
	}
}

// TestInstall_RejectsDeclaredOversizeBody: a declared Content-Length over the
// cap fails the request itself, before any of the body is read. A HEAD reply,
// which has no body, may declare any length.
func TestInstall_RejectsDeclaredOversizeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(MaxResponseBytes+1, 10))
		if r.Method == http.MethodHead {
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("a"))
	}))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrResponseTooLarge) || !strings.Contains(err.Error(), "Content-Length 67108865 is over 67108864 bytes") {
		t.Fatalf("expected the declared length to be refused, got: %v", err)
	}

	resp, err = http.Head(srv.URL)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	_ = resp.Body.Close()
	if resp.ContentLength != MaxResponseBytes+1 {
		t.Fatalf("HEAD must pass through, got Content-Length %d", resp.ContentLength)
	}
}

// TestGuard_PassesSwitchingProtocolsUntouched: a 101 response's body is the
// upgraded connection, so the guard must hand it on as it came.
func TestGuard_PassesSwitchingProtocolsUntouched(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("")}
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: body, ContentLength: -1, Header: http.Header{}}
	g := &guard{base: fakeTransport{resp: resp}, maxBytes: 1, maxLookupBytes: 1}
	got, err := g.RoundTrip(newRequest(t, http.MethodGet, "http://h/ws"))
	if err != nil || got != resp || got.Body != body {
		t.Fatalf("a 101 response must pass through untouched, got %+v, err %v", got, err)
	}
}

// TestGuard_ClosesRejectedBodies: every response the guard refuses has its
// body closed, so the connection is released.
func TestGuard_ClosesRejectedBodies(t *testing.T) {
	for _, tc := range []struct {
		name, method, url, contentType string
		body                           string
		contentLength                  int64
		want                           string
	}{
		{"declared over the cap", http.MethodGet, "http://h/x", "", "abc", 3, "Content-Length 3 is over 2 bytes"},
		{"lookup declared over its cap", http.MethodPost, "http://h/lookup", "", "abcd", 4, "lookup Content-Length 4 is over 3 bytes"},
		{"lookup streamed over its cap", http.MethodPost, "http://h/lookup", "", "abcd", -1, "lookup body is over 3 bytes"},
		{"invalid lookup answer", http.MethodPost, "http://h/lookup", "application/octet-stream", "\xFF", -1, "netguard: rejected lookup answer: binary lookup: reading outpoint count"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader(tc.body)}
			resp := &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: tc.contentLength, Header: http.Header{}}
			if tc.contentType != "" {
				resp.Header.Set("Content-Type", tc.contentType)
			}
			g := &guard{base: fakeTransport{resp: resp}, maxBytes: 2, maxLookupBytes: 3, readTimeout: time.Minute}
			got, err := g.RoundTrip(newRequest(t, tc.method, tc.url))
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error containing %q, got response %v, err %v", tc.want, got, err)
			}
			if !body.closed {
				t.Fatal("the refused response's body must be closed")
			}
		})
	}
}

// TestIsLookup: lookups are recognized however the facilitator's
// host + "/lookup" parses, and by the request that started a redirected
// exchange; nothing else is treated as one.
func TestIsLookup(t *testing.T) {
	post := func(url string) *http.Request { return newRequest(t, http.MethodPost, url) }
	aggregated := post("http://h/anything")
	aggregated.Header.Set("X-Aggregation", "yes")
	redirected := newRequest(t, http.MethodGet, "http://h/elsewhere")
	redirected.Response = &http.Response{Request: post("http://h/lookup")}
	redirectedSubmit := newRequest(t, http.MethodGet, "http://h/lookup")
	redirectedSubmit.Response = &http.Response{Request: post("http://h/submit")}

	for name, tc := range map[string]struct {
		req  *http.Request
		want bool
	}{
		"POST /lookup":                   {post("http://h/lookup"), true},
		"POST under a path":              {post("http://h/api/lookup"), true},
		"lookup in the query string":     {post("http://h/x?/lookup"), true},
		"lookup in the fragment":         {post("http://h/x#/lookup"), true},
		"X-Aggregation header":           {aggregated, true},
		"redirect follow-up of a lookup": {redirected, true},
		"redirect follow-up of a submit": {redirectedSubmit, false},
		"GET /lookup":                    {newRequest(t, http.MethodGet, "http://h/lookup"), false},
		"POST /submit":                   {post("http://h/submit"), false},
		"POST /lookups":                  {post("http://h/lookups"), false},
	} {
		if got := isLookup(tc.req); got != tc.want {
			t.Errorf("%s: isLookup = %v, want %v", name, got, tc.want)
		}
	}
}
