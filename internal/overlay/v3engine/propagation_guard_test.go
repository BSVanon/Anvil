package v3engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
)

// stubAdvertiser only has to be non-nil: go-overlay-services propagates an
// admitted submit only when the engine has an Advertiser.
type stubAdvertiser struct{}

var errStubAdvertiser = errors.New("stub advertiser")

func (stubAdvertiser) CreateAdvertisements([]*advertiser.AdvertisementData) (overlay.TaggedBEEF, error) {
	return overlay.TaggedBEEF{}, errStubAdvertiser
}

func (stubAdvertiser) FindAllAdvertisements(overlay.Protocol) ([]*advertiser.Advertisement, error) {
	return nil, nil
}

func (stubAdvertiser) RevokeAdvertisements([]*advertiser.Advertisement) (overlay.TaggedBEEF, error) {
	return overlay.TaggedBEEF{}, errStubAdvertiser
}

func (stubAdvertiser) ParseAdvertisement(*script.Script) (*advertiser.Advertisement, error) {
	return nil, errStubAdvertiser
}

// TestEngine_PropagationSurvivesHostileSLAPTracker: once engine.Submit admits
// a transaction, go-overlay-services v1.3.1 propagates it by building a stock
// go-sdk LookupResolver on http.DefaultClient (engine.go propagateToNetwork)
// and asking the engine's SLAP trackers for SHIP hosts, in a goroutine with
// no recover. A SLAP tracker answering with go-sdk's crash bodies (the 5-byte
// Atomic BEEF prefix, the 9-byte outpoint count that is a fatal out-of-memory
// error, the MaxInt64 context length that panics) used to take the whole node
// down with no login. With the DefaultClient guard, each of three admitted
// submits must query the tracker, survive its answer and return.
func TestEngine_PropagationSurvivesHostileSLAPTracker(t *testing.T) {
	hostile := [][]byte{
		{0x00, 0x01, 0x01, 0x01, 0x01},
		{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		append(append([]byte{0x01}, make([]byte, 33)...), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F),
	}
	var hits atomic.Int64
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(hostile[(n-1)%int64(len(hostile))])
	}))
	t.Cleanup(tracker.Close)

	eng, _ := newTestEngine(t)
	eng.Advertiser = stubAdvertiser{}
	eng.SLAPTrackers = []string{tracker.URL}

	for i := range hostile {
		hash := strings.Repeat(string("cde"[i]), 64)
		tagged := buildUHRPTaggedBEEF(t, hash, "https://example.test/p", "image/png", true)
		done := make(chan error, 1)
		go func() {
			steak, err := eng.Submit(context.Background(), tagged, engine.SubmitModeCurrent, nil)
			if ai := steak[topics.UHRPTopicName]; err == nil && (ai == nil || len(ai.OutputsToAdmit) != 1) {
				err = errors.New("the UHRP output was not admitted, so nothing was propagated")
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("submit %d: %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("submit %d did not return", i)
		}
		if got := hits.Load(); got < int64(i+1) {
			t.Fatalf("submit %d: propagation never queried the SLAP tracker (%d requests)", i, got)
		}
	}
}
