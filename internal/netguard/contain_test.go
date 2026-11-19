package netguard

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
)

// TestContain_RecoversTheBroadcasterNilDereference: on a client without the
// guard, a host answering the propagation POST /submit with "null" makes
// go-sdk's Broadcaster dereference a nil STEAK in the calling goroutine
// (topic/broadcaster.go:177). Contain turns that panic into an error wrapping
// ErrPanicked and logs the site, the panic and a stack that names the
// Broadcaster.
func TestContain_RecoversTheBroadcasterNilDereference(t *testing.T) {
	url, _ := steakHost(t, hostiletest.Literal("null", []byte(`null`)), false)
	b := stockBroadcaster(t, shipHostFor(t, []string{url}), &topic.HTTPSOverlayBroadcastFacilitator{Client: &http.Client{}})
	tx := broadcastTx(t)
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	err := Contain(logger, "propagation", func() error {
		_, _ = b.BroadcastCtx(context.Background(), tx)
		return nil
	})
	if !errors.Is(err, ErrPanicked) || !strings.Contains(err.Error(), "propagation") ||
		!strings.Contains(err.Error(), "nil pointer dereference") {
		t.Fatalf("want ErrPanicked naming the site and the nil dereference, got %v", err)
	}
	for _, want := range []string{"recovered a panic", "site=propagation", "nil pointer dereference", "overlay/topic/broadcaster.go:177"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("the log lacks %q:\n%s", want, logged.String())
		}
	}
}

// TestContain_PassesResultsThrough: without a panic, Contain returns what f
// returns and logs nothing; a nil logger logs a panic to slog.Default.
func TestContain_PassesResultsThrough(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	failed := errors.New("sync failed")
	if err := Contain(logger, "site", func() error { return failed }); err != failed {
		t.Fatalf("want f's error back, got %v", err)
	}
	if err := Contain(logger, "site", func() error { return nil }); err != nil {
		t.Fatalf("want nil back, got %v", err)
	}
	if logged.Len() != 0 {
		t.Fatalf("nothing panicked, but Contain logged:\n%s", logged.String())
	}

	previous, out, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(out) // SetDefault does not restore what it redirected
		log.SetFlags(flags)
	})
	slog.SetDefault(logger)
	if err := Contain(nil, "default", func() error { panic("boom") }); !errors.Is(err, ErrPanicked) {
		t.Fatalf("want ErrPanicked, got %v", err)
	}
	if !strings.Contains(logged.String(), "site=default") || !strings.Contains(logged.String(), "panic=boom") {
		t.Fatalf("a nil logger must log to slog.Default, got:\n%s", logged.String())
	}
}
