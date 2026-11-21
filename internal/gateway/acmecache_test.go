package gateway

import (
	"context"
	"crypto/tls"
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

// TestApplyReceived_CapAndLifetimeEnforced confirms the cap and
// lifetime are enforced, for the one entry shape (+http-01) this
// package tracks a lifetime for at all.
func TestApplyReceived_CapAndLifetimeEnforced(t *testing.T) {
	const senderHex = "0222222222222222222222222222222222222222222222222222222222222222"
	cache := NewCache(t.TempDir(), nil, nil, []string{senderHex}, nil)

	// Lifetime cap: a sender claiming an expiry far beyond
	// acmeHTTPTokenLifetime is capped down to it, not honoured as-is.
	if err := cache.ApplyReceived(senderHex, "longlived+http-01", []byte("x"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("ApplyReceived: %v", err)
	}
	cache.mu.Lock()
	gotExpiry := cache.httpTokens["longlived+http-01"]
	cache.mu.Unlock()
	if max := time.Now().Add(acmeHTTPTokenLifetime); gotExpiry.After(max) {
		t.Fatalf("tracked expiry %v exceeds the %v lifetime cap (max %v)", gotExpiry, acmeHTTPTokenLifetime, max)
	}

	// Entry cap: fill to acmeHTTPTokenCap, then one more new key must
	// be refused — but refreshing an existing key must still work.
	cache.mu.Lock()
	cache.httpTokens = make(map[string]time.Time, acmeHTTPTokenCap)
	for i := 0; i < acmeHTTPTokenCap; i++ {
		cache.httpTokens[testTxid(i)+"+http-01"] = time.Now().Add(acmeHTTPTokenLifetime)
	}
	cache.mu.Unlock()

	if err := cache.ApplyReceived(senderHex, testTxid(0)+"+http-01", []byte("refresh"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("refreshing an existing entry at the cap was refused: %v", err)
	}
	err := cache.ApplyReceived(senderHex, "brand-new-token+http-01", []byte("x"), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("ApplyReceived accepted a new entry past the cap")
	}
	if !errors.Is(err, errHTTPTokenAtCap) {
		t.Fatalf("error = %v, want errHTTPTokenAtCap", err)
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

// TestSiteCertState_NoneYet confirms a domain with no cached certificate
// and no recorded error reports Present=false — doctor's "none" state.
func TestSiteCertState_NoneYet(t *testing.T) {
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	state := cache.SiteCertState(context.Background(), "nothing-yet.example.org")
	if state.Present {
		t.Fatalf("Present = true for a domain with no cache entry")
	}
	if state.LastError != "" {
		t.Fatalf("LastError = %q, want empty", state.LastError)
	}
}

// TestSiteCertState_ValidUntilReflectsLeafExpiry seeds a real certificate
// blob (the same shape generateTestCertBlob produces for the handshake
// tests) and confirms SiteCertState reports Present=true with the leaf's
// actual NotAfter — doctor's "valid until" state.
func TestSiteCertState_ValidUntilReflectsLeafExpiry(t *testing.T) {
	const domain = "cert-state.example.org"
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	blob := generateTestCertBlob(t, domain)
	if err := cache.dir.Put(context.Background(), domain, blob); err != nil {
		t.Fatal(err)
	}

	state := cache.SiteCertState(context.Background(), domain)
	if !state.Present {
		t.Fatal("Present = false for a domain with a cached certificate")
	}
	if state.NotAfter.IsZero() {
		t.Fatal("NotAfter is zero for a cached certificate")
	}
	if state.NotAfter.Before(time.Now()) {
		t.Fatalf("NotAfter %v is in the past for a freshly seeded certificate", state.NotAfter)
	}
}

// TestRecordIssuanceError_SurfacesThroughSiteCertState confirms the note
// RecordIssuanceError writes is exactly what SiteCertState reads back —
// doctor's "last error" state, and the only way an error reaches doctor
// at all, since autocert itself keeps no durable record of one.
func TestRecordIssuanceError_SurfacesThroughSiteCertState(t *testing.T) {
	const domain = "error-state.example.org"
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	cache.RecordIssuanceError(domain, "acme: missing Manager.Prompt to accept server's terms of service")

	state := cache.SiteCertState(context.Background(), domain)
	if state.Present {
		t.Fatal("Present = true for a domain with only a recorded error, no certificate")
	}
	if state.LastError == "" {
		t.Fatal("LastError is empty after RecordIssuanceError")
	}
	if !strings.Contains(state.LastError, "missing Manager.Prompt") {
		t.Fatalf("LastError = %q, want it to contain the recorded message", state.LastError)
	}

	// A second call overwrites, rather than accumulates, the note.
	cache.RecordIssuanceError(domain, "a different error")
	state2 := cache.SiteCertState(context.Background(), domain)
	if strings.Contains(state2.LastError, "missing Manager.Prompt") {
		t.Fatalf("LastError = %q, want only the most recent note", state2.LastError)
	}
}

// TestWrapGetCertificate_RecordsNonRefusalErrorsOnly confirms
// wrapGetCertificate's errorRecorder wiring (tls.go): a HostPolicy
// refusal is never recorded as a site error (it's an access-control
// decision, not a certificate problem), while a genuine issuance error —
// here, AcceptTOS left false, so Manager.Prompt is nil — is.
func TestWrapGetCertificate_RecordsNonRefusalErrorsOnly(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir, nil, nil, nil, nil) // no Policy, no APIHost: every host is refused by HostPolicy
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache})
	get := wrapGetCertificate(manager, ensureCounters(nil), cache)

	if _, err := get(&tls.ClientHelloInfo{ServerName: "refused.example.org"}); err == nil {
		t.Fatal("expected HostPolicy to refuse an unlisted host")
	}
	if state := cache.SiteCertState(context.Background(), "refused.example.org"); state.LastError != "" {
		t.Fatalf("a HostPolicy refusal was recorded as a site error: %q", state.LastError)
	}

	// Now allow the host via APIHost, but leave AcceptTOS false: issuance
	// itself fails (no Manager.Prompt), which IS a recordable error.
	manager2 := NewACMEManager(ACMEManagerConfig{Cache: cache, APIHost: "allowed-but-no-tos.example.org"})
	get2 := wrapGetCertificate(manager2, ensureCounters(nil), cache)
	if _, err := get2(&tls.ClientHelloInfo{ServerName: "allowed-but-no-tos.example.org", CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}); err == nil {
		t.Fatal("expected issuance to fail with AcceptTOS left false")
	}
	if state := cache.SiteCertState(context.Background(), "allowed-but-no-tos.example.org"); state.LastError == "" {
		t.Fatal("a genuine issuance error (missing AcceptTOS) was not recorded")
	}
}
