package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeMesh stands in for a real mesh between two gateways: Put on one
// Cache calls send, which a test wires directly into a second Cache's
// ApplyReceived — no real gossip.Manager or network involved.
type fakeMesh struct {
	calls []fakeMeshCall
}

type fakeMeshCall struct {
	key     string
	value   []byte
	expires time.Time
}

func (f *fakeMesh) senderFor(senderPKHex string) ACMEPeerSender {
	return func(key string, value []byte, expires time.Time) int {
		f.calls = append(f.calls, fakeMeshCall{key: key, value: value, expires: expires})
		return 1
	}
}

// TestCachePut_ChallengeKeyReplicatesAcrossFakeMesh is the Tests
// section's "a +token or +http-01 put on gateway A appears on gateway B,
// through a fake mesh."
func TestCachePut_ChallengeKeyReplicatesAcrossFakeMesh(t *testing.T) {
	const senderHex = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(70, 0)}}
	policyB, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)

	mesh := &fakeMesh{}
	cacheA := NewCache(t.TempDir(), mesh.senderFor(senderHex), nil, []string{senderHex}, nil)
	cacheB := NewCache(t.TempDir(), nil, policyB, []string{senderHex}, nil)

	for _, key := range []string{"allowed.example.org+token", "sometoken+http-01"} {
		if err := cacheA.Put(context.Background(), key, []byte("value-for-"+key)); err != nil {
			t.Fatalf("Put(%q): %v", key, err)
		}
	}
	if len(mesh.calls) != 2 {
		t.Fatalf("fake mesh saw %d sends, want 2", len(mesh.calls))
	}

	for _, call := range mesh.calls {
		if err := cacheB.ApplyReceived(senderHex, call.key, call.value, call.expires); err != nil {
			t.Fatalf("ApplyReceived(%q): %v", call.key, err)
		}
		got, err := cacheB.Get(context.Background(), call.key)
		if err != nil {
			t.Fatalf("gateway B Get(%q) after replication: %v", call.key, err)
		}
		if string(got) != "value-for-"+call.key {
			t.Fatalf("gateway B got %q for %q, want the replicated value", got, call.key)
		}
	}
}

// TestCachePut_CertificateDoesNotReplicate confirms a certificate put
// does not replicate, and is also the first mutation check in reverse:
// this test fails if Put is changed to replicate every key, not only
// +token/+http-01 ones.
func TestCachePut_CertificateDoesNotReplicate(t *testing.T) {
	const senderHex = "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mesh := &fakeMesh{}
	cacheA := NewCache(t.TempDir(), mesh.senderFor(senderHex), nil, []string{senderHex}, nil)

	for _, key := range []string{
		"allowed.example.org",     // a plain ECDSA certificate
		"allowed.example.org+rsa", // the legacy RSA certificate
		"acme_account+key",        // the ACME account private key
		"acme_account.key",        // the legacy account key name
	} {
		if err := cacheA.Put(context.Background(), key, []byte("secret-for-"+key)); err != nil {
			t.Fatalf("Put(%q): %v", key, err)
		}
	}
	if len(mesh.calls) != 0 {
		t.Fatalf("fake mesh saw %d sends for non-challenge keys, want 0: %+v", len(mesh.calls), mesh.calls)
	}
}

// TestCachePut_CertificateIssuedCounter confirms a non-challenge,
// non-account-key Put increments CertIssued exactly once per such Put —
// the one place this package can tell a fresh issuance apart from a
// cache hit (see Put's doc comment).
func TestCachePut_CertificateIssuedCounter(t *testing.T) {
	counters := &Counters{}
	cacheA := NewCache(t.TempDir(), nil, nil, nil, counters)

	_ = cacheA.Put(context.Background(), "allowed.example.org", []byte("cert"))
	_ = cacheA.Put(context.Background(), "other.example.org+rsa", []byte("cert2"))
	_ = cacheA.Put(context.Background(), "acme_account+key", []byte("accountkey"))
	_ = cacheA.Put(context.Background(), "allowed.example.org+token", []byte("tok"))

	if got := counters.CertIssued.Load(); got != 2 {
		t.Fatalf("CertIssued = %d, want 2 (the account key and the token entry must not count)", got)
	}
}

// TestApplyReceived_RefusesSenderNotAllowed confirms an entry from a
// peer that isn't allowed is refused, and is also the third mutation
// check in reverse: fails if the allowed_peers check on received
// entries is ever skipped.
func TestApplyReceived_RefusesSenderNotAllowed(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(71, 0)}}
	policy, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, policy, []string{"02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, nil)

	err := cache.ApplyReceived("02dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"allowed.example.org+token", []byte("x"), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("ApplyReceived accepted an entry from a peer not in allowed_peers")
	}
	if !errors.Is(err, errSenderNotAllowed) {
		t.Fatalf("error = %v, want errSenderNotAllowed", err)
	}
	if _, getErr := cache.Get(context.Background(), "allowed.example.org+token"); getErr == nil {
		t.Fatal("the refused entry was written to the cache anyway")
	}
}

// TestApplyReceived_RefusesDomainNotAllowed confirms an entry for a
// domain that isn't allowed is refused.
func TestApplyReceived_RefusesDomainNotAllowed(t *testing.T) {
	const senderHex = "02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(72, 0)}}
	policy, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, policy, []string{senderHex}, nil)

	err := cache.ApplyReceived(senderHex, "not-allowed.example.org+token", []byte("x"), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("ApplyReceived accepted a +token entry for a domain this node doesn't allow")
	}
	if !errors.Is(err, errDomainNotAllowed) {
		t.Fatalf("error = %v, want errDomainNotAllowed", err)
	}
	if _, getErr := cache.Get(context.Background(), "not-allowed.example.org+token"); getErr == nil {
		t.Fatal("the refused entry was written to the cache anyway")
	}
}

// TestApplyReceived_HTTP01AcceptedWithoutDomainCheck confirms a
// "+http-01" entry is accepted from an allowed peer with no domain to
// check it against — Policy is nil here specifically to prove nothing
// about it is consulted for this key shape.
func TestApplyReceived_HTTP01AcceptedWithoutDomainCheck(t *testing.T) {
	const senderHex = "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	if err := cache.ApplyReceived(senderHex, "tok+http-01", []byte("key-auth"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("ApplyReceived refused a +http-01 entry from an allowed peer: %v", err)
	}
	got, err := cache.Get(context.Background(), "tok+http-01")
	if err != nil || string(got) != "key-auth" {
		t.Fatalf("Get(tok+http-01) = (%q, %v), want (key-auth, nil)", got, err)
	}
}

// TestApplyReceived_RefusesNonChallengeKey proves a certificate, +rsa
// or account-key shape is refused even when it arrives purporting to be
// a MsgACMEChallenge — defense in depth beyond the sender restriction
// acme_relay.go's own wire format already gives this (ACMEChallengePayload
// has no reason to ever carry one, but this method doesn't trust that).
func TestApplyReceived_RefusesNonChallengeKey(t *testing.T) {
	const senderHex = "0211111111111111111111111111111111111111111111111111111111111111"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(73, 0)}}
	policy, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, policy, []string{senderHex}, nil)

	for _, key := range []string{"allowed.example.org", "allowed.example.org+rsa", "acme_account+key"} {
		err := cache.ApplyReceived(senderHex, key, []byte("x"), time.Now().Add(time.Minute))
		if err == nil {
			t.Fatalf("ApplyReceived accepted non-challenge key %q", key)
		}
		if !errors.Is(err, errKeyNotReplicable) {
			t.Fatalf("key %q: error = %v, want errKeyNotReplicable", key, err)
		}
	}
}

// TestApplyReceived_RefusesHostileTokenDomain confirms a "+token" key
// whose domain part isn't a syntactically valid hostname is refused
// before anything else about it — including Policy — is consulted: a
// peer is never able to make this node write, or even evaluate a policy
// decision for, a key shaped like a path-traversal or malformed-hostname
// attempt. nil Policy here proves the point: if the shape check were
// skipped, the policy==nil branch would turn this into
// errDomainNotAllowed rather than errKeyNotReplicable.
func TestApplyReceived_RefusesHostileTokenDomain(t *testing.T) {
	const senderHex = "0212121212121212121212121212121212121212121212121212121212121212"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	for _, key := range []string{
		"../../x+token",
		"a/b.example+token",
		"..+token",
		"no-dot-at-all+token",
		strings.Repeat("a", 300) + ".example.org+token",
	} {
		err := cache.ApplyReceived(senderHex, key, []byte("x"), time.Now().Add(time.Minute))
		if err == nil {
			t.Fatalf("ApplyReceived accepted a hostile +token key %q", key)
		}
		if !errors.Is(err, errKeyNotReplicable) {
			t.Fatalf("key %q: error = %v, want errKeyNotReplicable", key, err)
		}
	}
}

// TestApplyReceived_RefusesHostileHTTPToken confirms a "+http-01" key
// whose token part isn't base64url-shaped is refused, the same way a
// hostile "+token" domain is.
func TestApplyReceived_RefusesHostileHTTPToken(t *testing.T) {
	const senderHex = "0213131313131313131313131313131313131313131313131313131313131313"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	for _, key := range []string{
		"../../x+http-01",
		"a/b+http-01",
		"tok with spaces+http-01",
		"tok\x00en+http-01",
		"+http-01", // empty token
	} {
		err := cache.ApplyReceived(senderHex, key, []byte("x"), time.Now().Add(time.Minute))
		if err == nil {
			t.Fatalf("ApplyReceived accepted a hostile +http-01 key %q", key)
		}
		if !errors.Is(err, errKeyNotReplicable) {
			t.Fatalf("key %q: error = %v, want errKeyNotReplicable", key, err)
		}
		if _, getErr := cache.Get(context.Background(), key); getErr == nil {
			t.Fatalf("the refused key %q was written to the cache anyway", key)
		}
	}
}

// TestApplyReceived_CapAndLifetimeEnforced confirms the cap and
// lifetime are enforced, for the one entry shape (+http-01) this
// package tracks a lifetime for at all.
func TestApplyReceived_CapAndLifetimeEnforced(t *testing.T) {
	const senderHex = "0222222222222222222222222222222222222222222222222222222222222222"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	// Lifetime cap: a sender claiming an expiry far beyond
	// acmeReplicatedEntryLifetime is capped down to it, not honoured as-is.
	if err := cache.ApplyReceived(senderHex, "longlived+http-01", []byte("x"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("ApplyReceived: %v", err)
	}
	cache.mu.Lock()
	gotExpiry := cache.replicatedEntries["longlived+http-01"]
	cache.mu.Unlock()
	if max := time.Now().Add(acmeReplicatedEntryLifetime); gotExpiry.After(max) {
		t.Fatalf("tracked expiry %v exceeds the %v lifetime cap (max %v)", gotExpiry, acmeReplicatedEntryLifetime, max)
	}

	// Entry cap: fill to acmeReplicatedEntryCap, then one more new key
	// must be refused — but refreshing an existing key must still work.
	cache.mu.Lock()
	cache.replicatedEntries = make(map[string]time.Time, acmeReplicatedEntryCap)
	for i := 0; i < acmeReplicatedEntryCap; i++ {
		cache.replicatedEntries[testTxid(i)+"+http-01"] = time.Now().Add(acmeReplicatedEntryLifetime)
	}
	cache.mu.Unlock()

	if err := cache.ApplyReceived(senderHex, testTxid(0)+"+http-01", []byte("refresh"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("refreshing an existing entry at the cap was refused: %v", err)
	}
	err := cache.ApplyReceived(senderHex, "brand-new-token+http-01", []byte("x"), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("ApplyReceived accepted a new entry past the cap")
	}
	if !errors.Is(err, errReplicatedEntryAtCap) {
		t.Fatalf("error = %v, want errReplicatedEntryAtCap", err)
	}
}

// TestApplyReceived_TokenEntryGetsCapAndLifetimeToo confirms a replicated
// "+token" entry is swept after its lifetime and counted against the
// cap exactly like a "+http-01" entry — the two are capped and expired
// the same way (applyCappedReplicatedEntryLocked), independently of each
// other (countReplicatedKindLocked), using a fake clock instead of a
// real sleep so the sweep is observed deterministically.
func TestApplyReceived_TokenEntryGetsCapAndLifetimeToo(t *testing.T) {
	const senderHex = "02551111111111111111111111111111111111111111111111111111111111aa"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(90, 0)}}
	policy, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, policy, []string{senderHex}, nil)

	start := time.Now()
	cache.now = func() time.Time { return start }

	if err := cache.ApplyReceived(senderHex, "allowed.example.org+token", []byte("x"), start.Add(24*time.Hour)); err != nil {
		t.Fatalf("ApplyReceived: %v", err)
	}
	cache.mu.Lock()
	gotExpiry := cache.replicatedEntries["allowed.example.org+token"]
	cache.mu.Unlock()
	if max := start.Add(acmeReplicatedEntryLifetime); gotExpiry.After(max) {
		t.Fatalf("tracked expiry %v exceeds the %v lifetime cap (max %v)", gotExpiry, acmeReplicatedEntryLifetime, max)
	}

	// Advance the fake clock past the lifetime: the next access sweeps
	// it, both from the accounting map and from disk.
	cache.now = func() time.Time { return start.Add(acmeReplicatedEntryLifetime + time.Second) }
	cache.mu.Lock()
	cache.evictExpiredReplicatedEntriesLocked()
	_, stillTracked := cache.replicatedEntries["allowed.example.org+token"]
	cache.mu.Unlock()
	if stillTracked {
		t.Fatal("a +token entry past its lifetime is still tracked")
	}
	if _, err := cache.Get(context.Background(), "allowed.example.org+token"); err == nil {
		t.Fatal("a +token entry past its lifetime is still readable from disk")
	}
}

// TestApplyReceived_ExpiredEntryRefused confirms an entry the sender
// already claims is expired is never written.
func TestApplyReceived_ExpiredEntryRefused(t *testing.T) {
	const senderHex = "0233333333333333333333333333333333333333333333333333333333333333"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	err := cache.ApplyReceived(senderHex, "tok+http-01", []byte("x"), time.Now().Add(-time.Second))
	if err == nil {
		t.Fatal("ApplyReceived accepted an already-expired entry")
	}
}

// TestNewCache_ReplicationDisabledWithEmptyAllowedPeers covers the case
// replication can't run at all: with no allowed_peers configured, Put
// never calls send, regardless of what send the caller supplied.
func TestNewCache_ReplicationDisabledWithEmptyAllowedPeers(t *testing.T) {
	mesh := &fakeMesh{}
	cache := NewCache(t.TempDir(), mesh.senderFor("irrelevant"), nil, nil, nil)

	if err := cache.Put(context.Background(), "allowed.example.org+token", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if len(mesh.calls) != 0 {
		t.Fatalf("fake mesh saw %d sends with allowed_peers empty, want 0", len(mesh.calls))
	}
}

// TestCachePut_ExpiresAtMost600sAhead confirms the expiry Put sends with
// a replicated entry is capped at acmeChallengeExpiryCap: at most 600s
// ahead.
func TestCachePut_ExpiresAtMost600sAhead(t *testing.T) {
	const senderHex = "0244444444444444444444444444444444444444444444444444444444444444"
	mesh := &fakeMesh{}
	cache := NewCache(t.TempDir(), mesh.senderFor(senderHex), nil, []string{senderHex}, nil)

	before := time.Now()
	if err := cache.Put(context.Background(), "tok+http-01", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if len(mesh.calls) != 1 {
		t.Fatalf("got %d sends, want 1", len(mesh.calls))
	}
	if max := before.Add(acmeChallengeExpiryCap + time.Second); mesh.calls[0].expires.After(max) {
		t.Fatalf("sent expires %v is more than %v ahead of the Put", mesh.calls[0].expires, acmeChallengeExpiryCap)
	}
}
