package gossip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/net/websocket"
)

// Transport-level mutation checks for B5 review BLOCKER 2: a refused peer
// must receive zero application messages, inbound and outbound. These use a
// bare go-sdk auth.Peer (not wrapped in a Manager) to count messages on the
// refused side, so the count is independent of Manager-side bookkeeping —
// which removePeerWithReason tears down on refusal, making it unsuitable for
// proving a negative about what was sent before that happened.
//
// Split from allowlist_test.go to keep that file under the project's
// line-count cap.

// rawCountingPeer wraps a bare auth.Peer (no Manager) around transport,
// counting every general message it receives. Used to stand in for "the
// other side" when the side under test is Anvil's real Manager code
// (ConnectPeer / ConnectSeedWithReconnect / AcceptPeer), so the count
// reflects only what that Manager code actually sent, not anything a second
// Manager's own announce logic might add.
type rawCountingPeer struct {
	peer     *auth.Peer
	received atomic.Int32
}

// newRawCountingPeerOn builds a rawCountingPeer on transport, authenticating
// as identityWallet. Start()/StartReceive() are both called, matching how
// Manager.ConnectPeer/AcceptPeer drive a real auth.Peer.
func newRawCountingPeerOn(t *testing.T, transport *ServerWSTransport, identityWallet auth.PeerOptions) *rawCountingPeer {
	t.Helper()
	rp := &rawCountingPeer{}
	rp.peer = auth.NewPeer(&identityWallet)
	rp.peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		rp.received.Add(1)
		return nil
	})
	if err := rp.peer.Start(); err != nil {
		t.Fatalf("raw peer start: %v", err)
	}
	go transport.StartReceive()
	return rp
}

// TestMeshAllowlist_OutboundRefusedPeerSendsNoMessages is the mutation check
// for the outbound half of BLOCKER 2: ConnectPeer must not send a refused
// remote anything derived from local state (topic interests, SHIP
// directory, catch-up requests) before its allowed_peers check runs. The
// remote here is a bare auth.Peer counting every general message it
// receives, independent of mgrA's own bookkeeping.
//
// If ConnectPeer's announceInterests/announceSHIP/requestCatchUp calls are
// moved back to before establishAndAuthorizePeer's allowlist check (the
// mutation this guards against), the remote's count goes to at least 1 and
// this test fails.
func TestMeshAllowlist_OutboundRefusedPeerSendsNoMessages(t *testing.T) {
	walletA, _ := newIdentity(t)
	remoteWallet, _ := newIdentity(t)

	// Buffered so the handler goroutine's send can never block past the
	// one value this test reads; the channel (not the raw variable) is
	// what establishes happens-before between that goroutine and this one.
	remoteCh := make(chan *rawCountingPeer, 1)
	handler := websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		remoteCh <- newRawCountingPeerOn(t, transport, auth.PeerOptions{Wallet: remoteWallet, Transport: transport})
		<-transport.Done()
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	// A only allows "stranger" -- the remote is refused once A learns its
	// identity, before A ever calls announceInterests/announceSHIP/
	// requestCatchUp.
	mgrA := newAllowlistTestManager(t, "outbound-nomsg-a", walletA, []string{strangerHex})
	err := mgrA.ConnectPeer(t.Context(), wsURL)
	if err == nil {
		t.Fatal("ConnectPeer: got nil error, want a refusal (errPeerRefused)")
	}

	// Give the remote's receive loop a moment to process anything that was
	// sent, so a regression that does send something has time to land
	// before we assert.
	time.Sleep(300 * time.Millisecond)

	var remote *rawCountingPeer
	select {
	case remote = <-remoteCh:
	case <-time.After(5 * time.Second):
		t.Fatal("remote handler never ran")
	}
	if got := remote.received.Load(); got != 0 {
		t.Fatalf("refused remote received %d application message(s), want 0", got)
	}
	if got := mgrA.PeerCount(); got != 0 {
		t.Fatalf("dialer PeerCount() = %d, want 0 (refused peer must be removed)", got)
	}
}

// TestMeshAllowlist_InboundRefusedPeerSendsNoMessages is the mutation check
// for the inbound half of BLOCKER 2: AcceptPeer must not reply to a refused
// dialer with anything derived from local state. mgrB is Anvil's real
// production accept path (MeshHandler); the dialer is a bare auth.Peer
// counting every general message it receives back, independent of mgrB's
// own bookkeeping.
//
// AcceptPeer can only learn a dialer's identity reactively (BRC-31 is
// mutual: the acceptor can't gate the handshake response itself, since
// completing it is how it learns who dialed in), so the dialer must send at
// least one general message before mgrB's allowlist check can run at all --
// this sends one and then asserts mgrB never replies with its own
// announces. If AcceptPeer's announceInterests/announceSHIP/requestCatchUp
// calls are moved back to unconditionally after Start() (the mutation this
// guards against), the dialer's count goes to at least 1 and this test
// fails.
func TestMeshAllowlist_InboundRefusedPeerSendsNoMessages(t *testing.T) {
	walletB, _ := newIdentity(t)
	dialerWallet, _ := newIdentity(t)

	// B only allows "stranger" -- the dialer is refused once B learns its
	// identity from the one message it sends below.
	mgrB := newAllowlistTestManager(t, "inbound-nomsg-b", walletB, []string{strangerHex})
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	transport, err := NewWSTransportAdapter(wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer transport.Close()
	dialer := newRawCountingPeerOn(t, transport, auth.PeerOptions{Wallet: dialerWallet, Transport: transport})

	// Send exactly one general message -- the minimum needed to reach
	// mgrB's allowlist check at all (see doc comment above). Its content is
	// irrelevant: handleMessage logs and drops anything it can't decode,
	// after the allowlist decision this test is proving has already run.
	if err := dialer.peer.ToPeer(t.Context(), []byte("ping"), nil, 5000); err != nil {
		t.Fatalf("dialer ToPeer: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if got := dialer.received.Load(); got != 0 {
		t.Fatalf("refused dialer received %d application message(s) back, want 0", got)
	}
	if got := mgrB.PeerCount(); got != 0 {
		t.Fatalf("listener PeerCount() = %d, want 0 (refused peer must be removed)", got)
	}
}

// TestMeshAllowlist_SeedRefusedBacksOffExponentially proves a seed refused
// by allowed_peers reconnects on a growing delay, not the flat interval a
// plain connect failure would retry at — this is the other half of BLOCKER
// 2 ("a refused seed's reconnect attempts back off"). With a flat interval,
// a 50ms interval would produce dozens of connect attempts in one second;
// the exponential refusal backoff (starting above the base interval,
// capped at maxRefusalBackoff) keeps it to a handful. This counts real
// WebSocket accepts on the listener side, independent of Manager-side
// bookkeeping.
func TestMeshAllowlist_SeedRefusedBacksOffExponentially(t *testing.T) {
	walletA, _ := newIdentity(t)
	walletB, _ := newIdentity(t)

	mgrB := newAllowlistTestManager(t, "seed-backoff-b", walletB, nil)
	var accepts atomic.Int32
	inner := mgrB.MeshHandler()
	ts := httptest.NewServer(httpCounter(&accepts, inner))
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	const interval = 50 * time.Millisecond
	mgrA := newAllowlistTestManager(t, "seed-backoff-a", walletA, []string{strangerHex})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go mgrA.ConnectSeedWithReconnect(ctx, wsURL, interval)

	// A flat interval retry would produce roughly 2s/50ms = 40 attempts.
	// The refusal backoff (starting at interval*2, doubling, capped at
	// maxRefusalBackoff) produces at most a handful in the same window:
	// ~0ms, ~100ms, ~300ms, ~700ms, ~1500ms -- 5 attempts.
	time.Sleep(2 * time.Second)
	cancel()

	if got := accepts.Load(); got > 8 {
		t.Fatalf("listener accepted %d connections in 2s, want <=8 (exponential backoff, not a flat %s retry)", got, interval)
	}
	if got := accepts.Load(); got < 1 {
		t.Fatalf("listener accepted %d connections in 2s, want at least 1 (the seed should have connected and been refused at least once)", got)
	}
}

// httpCounter wraps an http.Handler, counting every request it serves.
// Used to observe raw connection attempts independent of anything the
// wrapped Manager tracks internally.
func httpCounter(counter *atomic.Int32, inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.Add(1)
		inner.ServeHTTP(w, r)
	})
}
