package netguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type responseRoundTripper func(*http.Request) (*http.Response, error)

func (f responseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedResponseBody struct {
	reader *bytes.Reader
	reads  atomic.Int32
	closed atomic.Bool
}

func (b *observedResponseBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.reader.Read(p)
}

func (b *observedResponseBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestGuardReadsGASPErrorBodyBeforeReturning(t *testing.T) {
	want := []byte("peer busy")
	body := &observedResponseBody{reader: bytes.NewReader(want)}
	g := &guard{
		base: responseRoundTripper(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusServiceUnavailable,
				Body:          body,
				ContentLength: int64(len(want)),
				Header:        make(http.Header),
				Request:       r,
			}, nil
		}),
		maxBytes:      MaxResponseBytes,
		headerTimeout: time.Second,
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://peer.test/requestSyncResponse", nil)

	resp, err := g.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if body.reads.Load() == 0 || !body.closed.Load() {
		t.Fatalf("error body returned without a bounded eager read: reads=%d closed=%v", body.reads.Load(), body.closed.Load())
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read buffered body: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestGuardCapsGASPSuccessAndErrorBodies(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &observedResponseBody{reader: bytes.NewReader(make([]byte, 65))}
			g := &guard{
				base: responseRoundTripper(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: status, Body: body, ContentLength: -1,
						Header: make(http.Header), Request: r,
					}, nil
				}),
				maxBytes: 64,
			}
			req, _ := http.NewRequest(http.MethodPost, "https://peer.test/requestSyncResponse", nil)

			resp, err := g.RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("status %d: error = %v, want ErrResponseTooLarge", status, err)
			}
			if !body.closed.Load() {
				t.Fatalf("status %d: oversized body was not closed", status)
			}
		})
	}
}

type gatedResponseBody struct {
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *gatedResponseBody) Read([]byte) (int, error) {
	b.once.Do(func() { b.entered <- struct{}{} })
	<-b.release
	return 0, io.EOF
}

func (*gatedResponseBody) Close() error { return nil }

func TestGuardBoundsConcurrentGASPResponseReads(t *testing.T) {
	const requests = 5
	entered := make(chan struct{}, requests)
	release := make(chan struct{})
	var closeRelease sync.Once
	t.Cleanup(func() { closeRelease.Do(func() { close(release) }) })

	g := &guard{
		base: responseRoundTripper(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Body:          &gatedResponseBody{entered: entered, release: release},
				ContentLength: -1,
				Header:        make(http.Header),
				Request:       r,
			}, nil
		}),
		maxBytes: 1 << 20,
	}
	results := make(chan *http.Response, requests)
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() {
			req, _ := http.NewRequest(http.MethodPost, "https://peer.test/requestSyncResponse", nil)
			resp, err := g.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			results <- resp
		}()
	}

	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case err := <-errs:
			t.Fatalf("GASP read %d: %v", i, err)
		case <-time.After(time.Second):
			t.Fatalf("only %d GASP reads entered", i)
		}
	}
	select {
	case <-entered:
		closeRelease.Do(func() { close(release) })
		t.Fatal("a fifth GASP body read entered before one of four bounded reads finished")
	case <-time.After(100 * time.Millisecond):
	}

	closeRelease.Do(func() { close(release) })
	for i := 0; i < 4; i++ {
		select {
		case resp := <-results:
			_ = resp.Body.Close()
		case err := <-errs:
			t.Fatalf("GASP read %d: %v", i, err)
		case <-time.After(time.Second):
			t.Fatal("bounded GASP read did not return")
		}
	}
	select {
	case <-entered:
	case err := <-errs:
		t.Fatalf("queued GASP read: %v", err)
	case <-time.After(time.Second):
		t.Fatal("queued GASP read did not enter after a permit was released")
	}
	select {
	case resp := <-results:
		_ = resp.Body.Close()
	case err := <-errs:
		t.Fatalf("queued GASP read: %v", err)
	case <-time.After(time.Second):
		t.Fatal("queued GASP read did not return")
	}
}
