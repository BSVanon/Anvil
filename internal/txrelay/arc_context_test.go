package txrelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingARC is a mock ARC that counts the submits it receives and answers
// each one with handle.
func countingARC(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// Submit still fails over to the secondary when the primary fails.
func TestARCClientSubmitFailsOverToTheSecondary(t *testing.T) {
	primary, _ := countingARC(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	secondary, hits := countingARC(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ARCResponse{TxID: "abc", Status: "SEEN_ON_NETWORK"})
	})
	client := NewARCClient(primary.URL, "")
	client.SetFailover(secondary.URL, "")
	resp, err := client.Submit([]byte{0x01})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if resp.Status != "SEEN_ON_NETWORK" || hits.Load() != 1 {
		t.Fatalf("got status %q after %d secondary submits, want SEEN_ON_NETWORK after 1", resp.Status, hits.Load())
	}
}

// SubmitContext ends when its context does, while ARC is still holding the
// request, and does not then try the secondary.
func TestARCClientSubmitContextEndsWithItsContext(t *testing.T) {
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	primary, _ := countingARC(t, func(_ http.ResponseWriter, r *http.Request) {
		// Reading the body to its end lets the server see the client go.
		_, _ = io.ReadAll(r.Body)
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) }) // before the server closes
	secondary, hits := countingARC(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ARCResponse{TxID: "abc", Status: "SEEN_ON_NETWORK"})
	})
	client := NewARCClient(primary.URL, "")
	client.SetFailover(secondary.URL, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.SubmitContext(ctx, []byte{0x01})
		done <- err
	}()
	<-arrived
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SubmitContext after its context ended: got %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SubmitContext did not end when its context did")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the secondary got %d submits after the context ended, want 0", n)
	}
}
