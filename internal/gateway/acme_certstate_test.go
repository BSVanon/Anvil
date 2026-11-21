package gateway

// Certificate-state reporting (SiteCertState, RecordIssuanceError) and
// the one place a raw, unauthenticated TLS ClientHello name can reach a
// filesystem path (wrapGetCertificate, tls.go): every test here writes
// through one of RecordIssuanceError/wrapGetCertificate and reads back
// through SiteCertState, the same round trip doctor relies on.

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// TestRecordIssuanceError_HostileDomainsNeverTouchFilesystem calls
// Cache.RecordIssuanceError directly with the same hostile domain shapes
// TestWrapGetCertificate_HostileNamesNeverTouchFilesystem sends through
// the full request path — but bypassing wrapGetCertificate entirely.
// That other test only proves HostPolicy refuses these names before
// RecordIssuanceError is ever reached (no Policy/APIHost is configured
// there, so every hostile ServerName is refused before recordableHost
// would even consider recording it); it never actually calls
// RecordIssuanceError with a hostile domain, so it can't prove this
// method is safe on its own, independent of every caller always having
// policy-checked first. This test closes that gap directly: nothing is
// written outside the acme directory, and no "+lasterror" file is
// created inside it, for any of these domains.
func TestRecordIssuanceError_HostileDomainsNeverTouchFilesystem(t *testing.T) {
	outerDir := t.TempDir()
	acmeDir := filepath.Join(outerDir, "acme")
	cache := NewCache(acmeDir, nil, nil, nil, nil)

	hostile := []string{
		"../../x",
		"a/b.example",
		"..",
		"nul\x00byte.example",
		strings.Repeat("a", 300) + ".example.org",
	}
	for _, name := range hostile {
		cache.RecordIssuanceError(name, "direct call, bypassing wrapGetCertificate")
	}

	entries, err := os.ReadDir(outerDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "acme" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("outside the acme directory, found %v, want exactly [acme] and nothing else", names)
	}

	acmeEntries, err := os.ReadDir(acmeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(acmeEntries) != 0 {
		names := make([]string, 0, len(acmeEntries))
		for _, e := range acmeEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("acme directory contains %v after only hostile, direct RecordIssuanceError calls, want none", names)
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

// TestWrapGetCertificate_HostileNamesNeverTouchFilesystem sends several
// hostile TLS ClientHello ServerNames — the shapes a pre-auth attacker
// dialing straight into 443 can put there, before any certificate, any
// HostPolicy allow-decision, or any ACME exchange has happened — through
// the real wrapGetCertificate path, and confirms none of them leaves any
// trace on disk: no file anywhere outside the acme cache directory, and
// no "+lasterror" note inside it either. No Policy and no APIHost means
// HostPolicy itself already refuses every one of these before an
// issuance attempt even starts, so this also doubles as proof that a
// HostPolicy refusal alone never touches the filesystem.
func TestWrapGetCertificate_HostileNamesNeverTouchFilesystem(t *testing.T) {
	outerDir := t.TempDir()
	acmeDir := filepath.Join(outerDir, "acme")
	cache := NewCache(acmeDir, nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache})
	get := wrapGetCertificate(manager, ensureCounters(nil), cache)

	hostile := []string{
		"../../x",
		"a/b.example",
		"..",
		"nul\x00byte.example",
		strings.Repeat("a", 300) + ".example.org",
	}
	for _, name := range hostile {
		if _, err := get(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("expected %q to be refused", name)
		}
	}

	entries, err := os.ReadDir(outerDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "acme" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("outside the acme directory, found %v, want exactly [acme] and nothing else", names)
	}

	acmeEntries, err := os.ReadDir(acmeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(acmeEntries) != 0 {
		names := make([]string, 0, len(acmeEntries))
		for _, e := range acmeEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("acme directory contains %v after only hostile, refused requests, want none", names)
	}
}

// TestWrapGetCertificate_NormalisesCaseBeforeRecording confirms a
// mixed-case ClientHello ServerName is normalised to lowercase before
// it decides anything: UPPER.Example is the same host as its sites-file
// entry "upper.example", recordableHost's policy re-check allows it, and
// the issuance error that follows (AcceptTOS left false) is recorded
// under the normalised name — and reading it back is case-insensitive
// too (errorNotePath normalises the SiteCertState side of the round
// trip exactly the same way), so doctor's own lookup can never miss a
// note purely because of how a domain happened to be spelled.
func TestWrapGetCertificate_NormalisesCaseBeforeRecording(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(91, 0)}}
	policy, _, _ := newTestPolicy(t, "domain upper.example\n", fake)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: policy}) // AcceptTOS left false
	get := wrapGetCertificate(manager, ensureCounters(nil), cache)

	if _, err := get(&tls.ClientHelloInfo{
		ServerName:   "UPPER.Example",
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}); err == nil {
		t.Fatal("expected issuance to fail with AcceptTOS left false")
	}

	lower := cache.SiteCertState(context.Background(), "upper.example")
	if lower.LastError == "" {
		t.Fatal("a genuine issuance error for an allowed, mixed-case host was not recorded under its normalised name")
	}
	mixed := cache.SiteCertState(context.Background(), "UPPER.Example")
	if mixed.LastError != lower.LastError {
		t.Fatalf("SiteCertState(%q) = %q, want the same note as SiteCertState(%q) = %q — the lookup must normalise case the same way recording does",
			"UPPER.Example", mixed.LastError, "upper.example", lower.LastError)
	}
}

// TestWrapGetCertificate_TokenCertBypassStillGatedByPolicy covers the
// one case errorNotePath's own hostname-syntax check can't catch by
// itself: a syntactically valid domain nobody configured, reached
// through autocert's tls-alpn-01 "+token" bypass (wantsTokenCert,
// golang.org/x/crypto@v0.59.0/acme/autocert/autocert.go:276-288), which
// never calls HostPolicy at all — confirmed directly by
// TestHTTPSHandshake_ACMETLS1HelloGetsTokenCert's doc comment, and here
// by asserting the returned error does NOT wrap errHostNotAllowed (that
// sentinel can only come from HostPolicy, so its absence proves
// HostPolicy was never consulted for this request). No "+token" entry
// is seeded, so the lookup fails with a plain "no token cert" error —
// autocert.go:286 confirms this is a direct cache-miss return, never a
// network call to an ACME directory, so this test can't reach the
// network. Because recordableHost re-checks the policy itself before
// recording, no "+lasterror" note is written for this domain even
// though the error reaching wrapGetCertificate never carried
// errHostNotAllowed — the one case where "did HostPolicy already
// refuse this" is the wrong question, and "does the policy allow this
// host right now" (recordableHost's actual question) is the one that
// matters.
func TestWrapGetCertificate_TokenCertBypassStillGatedByPolicy(t *testing.T) {
	const domain = "never-configured.example.org"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(92, 0)}}
	policy, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake) // domain is not in this list
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: policy})
	get := wrapGetCertificate(manager, ensureCounters(nil), cache)

	_, err := get(&tls.ClientHelloInfo{ServerName: domain, SupportedProtos: []string{"acme-tls/1"}})
	if err == nil {
		t.Fatal("expected the +token lookup to fail: nothing was ever seeded for this domain")
	}
	if errors.Is(err, errHostNotAllowed) {
		t.Fatal("got errHostNotAllowed — the tls-alpn-01 bypass path never calls HostPolicy, so this error can't be that sentinel")
	}
	if state := cache.SiteCertState(context.Background(), domain); state.LastError != "" {
		t.Fatalf("a +lasterror note was written for %q, a domain this gateway's policy never allowed", domain)
	}
}
