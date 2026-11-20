package gossip

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// strangerHex is a syntactically plausible compressed-pubkey hex that never
// corresponds to any wallet created in these tests — used as an
// allowed_peers entry that the peer under test is guaranteed not to match.
const strangerHex = "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// --- unit level: peerAllowlist in isolation, no network involved ---

// TestPeerAllowlist_UnsetIsUnrestricted is the mutation check for the hard
// constraint that an empty/unset allowed_peers leaves today's behaviour
// (accept any peer) byte-for-byte unchanged: nil, an empty slice, and a
// slice of only blank/whitespace entries must all disable the restriction.
func TestPeerAllowlist_UnsetIsUnrestricted(t *testing.T) {
	cases := [][]string{nil, {}, {""}, {"  ", "\t"}}
	for _, hexKeys := range cases {
		a := newPeerAllowlist(hexKeys)
		if a.enabled() {
			t.Errorf("newPeerAllowlist(%#v).enabled() = true, want false", hexKeys)
		}
		if !a.allows("0000000000000000000000000000000000000000000000000000000000000000") {
			t.Errorf("newPeerAllowlist(%#v).allows(...) = false, want true when disabled", hexKeys)
		}
	}
}

// TestPeerAllowlist_MembershipIsCaseInsensitive mirrors how identity hex is
// produced elsewhere in this package (fmt.Sprintf("%x", ...), always
// lowercase) but guards against a configured value using upper case.
func TestPeerAllowlist_MembershipIsCaseInsensitive(t *testing.T) {
	a := newPeerAllowlist([]string{"ABCDEF01"})
	if !a.enabled() {
		t.Fatal("expected allowlist to be enabled with one non-blank entry")
	}
	if !a.allows("abcdef01") {
		t.Error(`allows("abcdef01") = false, want true (lowercase match)`)
	}
	if !a.allows("AbCdEf01") {
		t.Error(`allows("AbCdEf01") = false, want true (mixed-case match)`)
	}
	if a.allows("abcdef02") {
		t.Error(`allows("abcdef02") = true, want false (not listed)`)
	}
}

// TestPeerAllowlist_RefusalLogRateLimited proves repeated refusals from the
// same identity log once per allowedPeerRefusalLogInterval, not once per
// attempt, while a different identity gets its own independent window.
func TestPeerAllowlist_RefusalLogRateLimited(t *testing.T) {
	a := newPeerAllowlist([]string{"deadbeef"})
	now := time.Now()
	if !a.shouldLog("abc123", now) {
		t.Fatal("first refusal for a new identity should log")
	}
	if a.shouldLog("abc123", now.Add(time.Second)) {
		t.Fatal("a second refusal within the rate-limit window should not log")
	}
	if !a.shouldLog("abc123", now.Add(allowedPeerRefusalLogInterval+time.Second)) {
		t.Fatal("a refusal after the rate-limit window elapses should log again")
	}
	if !a.shouldLog("other", now) {
		t.Fatal("a different identity has its own rate-limit bucket")
	}
}

// --- integration level: enforcement at the live BRC-31 handshake sites ---

// newIdentity returns a go-sdk TestWallet backed by a fresh random key, plus
// the hex identity string the Manager computes for it once connected
// (fmt.Sprintf("%x", pubkey.Compressed()) — see ConnectPeer/AcceptPeer).
func newIdentity(t *testing.T) (wallet.Interface, string) {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	w := wallet.NewTestWallet(t, key)
	return w, fmt.Sprintf("%x", key.PubKey().Compressed())
}

// newAllowlistTestManager builds a Manager with a temp envelope store,
// closed via t.Cleanup, for the mesh-level allowlist tests below.
func newAllowlistTestManager(t *testing.T, name string, w wallet.Interface, allowedPeers []string) *Manager {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-allow-"+name+"-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatalf("new envelope store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	m := NewManager(ManagerConfig{
		Wallet:         w,
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		AllowedPeers:   allowedPeers,
	})
	t.Cleanup(m.Stop)
	return m
}

// TestMeshAllowlist_InboundNotListedIsRefused proves AcceptPeer's
// allowed_peers enforcement: the LISTENER's own allowed_peers decides
// whether a dialing peer stays connected, independent of whatever the
// dialer configured for itself.
func TestMeshAllowlist_InboundNotListedIsRefused(t *testing.T) {
	walletA, _ := newIdentity(t)
	walletB, _ := newIdentity(t)

	// B only allows "stranger" -- A is refused inbound.
	mgrB := newAllowlistTestManager(t, "inbound-b", walletB, []string{strangerHex})
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	mgrA := newAllowlistTestManager(t, "inbound-a", walletA, nil)
	if err := mgrA.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}

	// Give the handshake time to complete and the allowlist check (synchronous
	// within the identity-reveal callback) time to run and remove the peer.
	time.Sleep(1 * time.Second)

	if got := mgrB.PeerCount(); got != 0 {
		t.Fatalf("listener PeerCount() = %d, want 0 (peer not in allowed_peers must be refused)", got)
	}
}

// TestMeshAllowlist_OutboundNotListedIsRefused proves ConnectPeer's
// allowed_peers enforcement: the DIALER's own allowed_peers decides whether
// it keeps talking to a peer it just connected to, independent of whatever
// the remote side configured. ConnectPeer completes the handshake and the
// allowlist check synchronously, before ever announcing anything to the
// remote (see establishAndAuthorizePeer) — so unlike the inbound case, a
// refusal surfaces as an error from ConnectPeer itself, not only as
// PeerCount() settling back to 0 sometime later.
func TestMeshAllowlist_OutboundNotListedIsRefused(t *testing.T) {
	walletA, _ := newIdentity(t)
	walletB, _ := newIdentity(t)

	mgrB := newAllowlistTestManager(t, "outbound-b", walletB, nil)
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	// A only allows "stranger" -- B is refused once A learns B's identity.
	mgrA := newAllowlistTestManager(t, "outbound-a", walletA, []string{strangerHex})
	err := mgrA.ConnectPeer(t.Context(), wsURL)
	if !errors.Is(err, errPeerRefused) {
		t.Fatalf("ConnectPeer: got error %v, want errPeerRefused", err)
	}

	if got := mgrA.PeerCount(); got != 0 {
		t.Fatalf("dialer PeerCount() = %d, want 0 (peer not in allowed_peers must be refused)", got)
	}
}

// TestMeshAllowlist_BothListedStaysConnectedAndFunctions proves the
// allowlist does not interfere with a permitted peer: both sides list each
// other's identity, the connection establishes and remains up, and gossip
// still flows end to end -- "stays" means the mesh keeps working, not just
// that a peer count is briefly nonzero.
func TestMeshAllowlist_BothListedStaysConnectedAndFunctions(t *testing.T) {
	walletA, hexA := newIdentity(t)
	walletB, hexB := newIdentity(t)

	var receivedMu sync.Mutex
	var receivedTopic string
	receivedCh := make(chan struct{}, 1)

	dirB, err := os.MkdirTemp("", "anvil-allow-both-b-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dirB) })
	storeB, err := envelope.NewStore(dirB, 3600, 65536)
	if err != nil {
		t.Fatalf("new envelope store: %v", err)
	}
	t.Cleanup(func() { storeB.Close() })

	mgrB := NewManager(ManagerConfig{
		Wallet:         walletB,
		Store:          storeB,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		AllowedPeers:   []string{hexA},
		OnEnvelope: func(env *envelope.Envelope) {
			receivedMu.Lock()
			receivedTopic = env.Topic
			receivedMu.Unlock()
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		},
	})
	t.Cleanup(mgrB.Stop)

	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	mgrA := newAllowlistTestManager(t, "both-a", walletA, []string{hexB})
	if err := mgrA.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}

	time.Sleep(1 * time.Second)

	if got := mgrA.PeerCount(); got != 1 {
		t.Fatalf("dialer PeerCount() = %d, want 1 (listed peer must stay connected)", got)
	}
	if got := mgrB.PeerCount(); got != 1 {
		t.Fatalf("listener PeerCount() = %d, want 1 (listed peer must stay connected)", got)
	}

	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate envelope key: %v", err)
	}
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:allowlist",
		Payload:   `{"rate":1}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	mgrA.BroadcastEnvelope(env)

	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for envelope to reach the listed peer -- allowlist must not block gossip")
	}

	receivedMu.Lock()
	got := receivedTopic
	receivedMu.Unlock()
	if got != "oracle:rates:allowlist" {
		t.Fatalf("received topic = %q, want oracle:rates:allowlist", got)
	}
}

// pollPeerCountSettles polls mgr.PeerCount() every 100ms until it has read
// want for consecutiveHits samples in a row, or fails the test once timeout
// elapses. ConnectSeedWithReconnect's retry loop makes a single
// instant-in-time check timing-sensitive: a sample can land in the brief
// window where a reconnect attempt has just been accepted but the
// identity-reveal callback (where allowed_peers is enforced) hasn't run
// yet, which is a real but transient state, not the steady state under
// test. Requiring several consecutive matching samples proves the count
// has settled rather than been caught mid-cycle.
func pollPeerCountSettles(t *testing.T, mgr *Manager, want, consecutiveHits int, timeout time.Duration) {
	t.Helper()
	const sampleInterval = 100 * time.Millisecond
	deadline := time.Now().Add(timeout)
	hits := 0
	lastSeen := -1
	for time.Now().Before(deadline) {
		lastSeen = mgr.PeerCount()
		if lastSeen == want {
			hits++
			if hits >= consecutiveHits {
				return
			}
		} else {
			hits = 0
		}
		time.Sleep(sampleInterval)
	}
	t.Fatalf("PeerCount() did not settle at %d for %d consecutive samples within %s; last seen %d", want, consecutiveHits, timeout, lastSeen)
}

// TestMeshAllowlist_SeedNotListedIsDropped proves allowed_peers enforcement
// at the actual production seed-dialing path, ConnectSeedWithReconnect
// (invoked from main.go for every [mesh] seeds entry) -- not just the
// test-only ConnectPeer used by the cases above.
//
// ConnectSeedWithReconnect retries on a fixed interval, so while it keeps
// running there is no steady state to sample: each cycle is briefly
// connected (PeerCount 1) before the handshake-driven refusal removes it
// (PeerCount 0), and under heavy contention a fixed poll cadence can alias
// with the retry cadence and keep landing on 1. Letting a couple of cycles
// run, then cancelling the loop, removes that ambiguity: once cancelled, no
// further reconnect attempt can start (ConnectSeedWithReconnect checks
// ctx.Done() before every retry), so the one in-flight attempt the
// cancellation race can still let through is the last thing that will ever
// touch this manager's peer count, and its own handshake-driven refusal
// (independent of ctx) cleans it up deterministically.
func TestMeshAllowlist_SeedNotListedIsDropped(t *testing.T) {
	walletA, _ := newIdentity(t)
	walletB, _ := newIdentity(t)

	mgrB := newAllowlistTestManager(t, "seed-refused-b", walletB, nil)
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	mgrA := newAllowlistTestManager(t, "seed-refused-a", walletA, []string{strangerHex})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel() // safety net if the test fails before the explicit cancel below
	go mgrA.ConnectSeedWithReconnect(ctx, wsURL, 100*time.Millisecond)

	time.Sleep(500 * time.Millisecond) // let at least one connect/refuse cycle complete
	cancel()                           // stop further reconnect attempts

	pollPeerCountSettles(t, mgrA, 0, 3, 5*time.Second)
}

// TestMeshAllowlist_SeedListedStaysConnected is the positive control for the
// test above: the same production seed-dialing path, but with the remote
// identity listed, must connect and stay connected.
func TestMeshAllowlist_SeedListedStaysConnected(t *testing.T) {
	walletA, _ := newIdentity(t)
	walletB, hexB := newIdentity(t)

	mgrB := newAllowlistTestManager(t, "seed-ok-b", walletB, nil)
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	mgrA := newAllowlistTestManager(t, "seed-ok-a", walletA, []string{hexB})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go mgrA.ConnectSeedWithReconnect(ctx, wsURL, 100*time.Millisecond)

	pollPeerCountSettles(t, mgrA, 1, 5, 10*time.Second)
}
