package v3engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// namedPeerServer is a minimal httptest server standing in for one
// [overlay] named_peers entry. It records the path of every request it
// receives and answers 503 to all of them, so GASP's single
// GetInitialResponse attempt and the broadcaster's SLAP query / submit each
// fail fast and cleanly with no real overlay peer on the other end -- the
// server exists only to prove it was (or was not) contacted.
type namedPeerServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newNamedPeerServer(t *testing.T) *namedPeerServer {
	t.Helper()
	s := &namedPeerServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *namedPeerServer) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

// namedPeersSyncConfiguration mirrors the named_peers branch of
// buildSyncConfiguration in cmd/anvil/federation_loops.go: every topic the
// engine hosts gets SyncConfigurationPeers seeded with namedPeers instead of
// SHIP-lookup discovery. Reproduced here rather than imported -- cmd/anvil
// is package main -- so this test drives the real engine.StartGASPSync
// behaviour for that exact shape.
func namedPeersSyncConfiguration(eng *engine.Engine, namedPeers []string) map[string]engine.SyncConfiguration {
	out := map[string]engine.SyncConfiguration{}
	for name := range eng.ListTopicManagers() {
		out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: namedPeers}
	}
	return out
}

// TestNamedPeers_GASPSyncTargetsOnlyNamedPeers proves that once
// SyncConfiguration is shaped the way [overlay] named_peers requires (every
// topic forced to SyncConfigurationPeers; see buildSyncConfiguration),
// engine.StartGASPSync's peer catch-up (syncWithPeer ->
// NewOverlayGASPRemote, go-overlay-services v1.3.1 engine.go:1117-1139)
// contacts every named peer -- and, because no topic is
// SyncConfigurationSHIP, never runs discoverSHIPPeers (engine.go:
// 1016-1066, the only caller of LookupResolver.Query) at all.
// LookupResolver is deliberately left nil: discoverSHIPPeers would panic on
// a nil resolver if that code path were still reachable, so StartGASPSync
// returning cleanly is itself part of the proof that lookup federation
// (the same SHIP-lookup mechanism) is architecturally unreachable in this
// mode, not merely unused on this run.
func TestNamedPeers_GASPSyncTargetsOnlyNamedPeers(t *testing.T) {
	peerA := newNamedPeerServer(t)
	peerB := newNamedPeerServer(t)
	namedPeers := []string{peerA.URL, peerB.URL}

	eng, _ := newTestEngine(t)
	eng.SHIPTrackers = namedPeers
	eng.SLAPTrackers = namedPeers
	eng.SyncConfiguration = namedPeersSyncConfiguration(eng, namedPeers)

	if err := eng.StartGASPSync(context.Background()); err != nil {
		t.Fatalf("StartGASPSync: %v", err)
	}

	if peerA.hitCount() == 0 {
		t.Error("GASP sync never contacted named peer A")
	}
	if peerB.hitCount() == 0 {
		t.Error("GASP sync never contacted named peer B")
	}
}

// TestNamedPeers_SubmitPropagationTargetsOnlyNamedPeers proves that once
// [overlay] named_peers has set e.SLAPTrackers (as wireV3Federation in
// cmd/anvil/federation_loops.go does), engine.Submit's propagateToNetwork
// (engine.go:689-718) -- which builds a fresh go-sdk lookup.LookupResolver
// and topic.Broadcaster scoped to e.SLAPTrackers for every submission whose
// mode is not SubmitModeHistorical -- queries the named peer for interested
// hosts instead of a public/default SLAP tracker. stubAdvertiser (defined
// in propagation_guard_test.go) only needs to be non-nil: propagateToNetwork
// gates on e.Advertiser != nil and does not otherwise call through it for a
// plain data submission.
func TestNamedPeers_SubmitPropagationTargetsOnlyNamedPeers(t *testing.T) {
	peer := newNamedPeerServer(t)
	namedPeers := []string{peer.URL}

	eng, _ := newTestEngine(t)
	eng.Advertiser = stubAdvertiser{}
	eng.SLAPTrackers = namedPeers

	hashHex := strings.Repeat("c", 64)
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/c", "image/png", true)

	if _, err := eng.Submit(context.Background(), tagged, engine.SubmitModeCurrent, nil); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if peer.hitCount() == 0 {
		t.Fatal("submit propagation never contacted the named peer (expected a SLAP lookup for interested hosts)")
	}
}
