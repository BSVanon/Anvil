package certgate

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type fakeWatcher struct {
	mu       sync.Mutex
	spent    bool
	checkErr error
	watchErr error
	checks   int
	watched  map[string]bool
	callback func(string, string)
}

func newFakeWatcher() *fakeWatcher { return &fakeWatcher{watched: map[string]bool{}} }

func (w *fakeWatcher) Check(context.Context, string) (bool, string, error) {
	w.mu.Lock()
	w.checks++
	w.mu.Unlock()
	return w.spent, "", w.checkErr
}
func (w *fakeWatcher) Watch(outpoint, _ string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.watchErr != nil {
		return w.watchErr
	}
	w.watched[outpoint] = true
	return nil
}
func (w *fakeWatcher) Unwatch(outpoint, _ string) {
	w.mu.Lock()
	delete(w.watched, outpoint)
	w.mu.Unlock()
}
func (w *fakeWatcher) OnSpent(_ string, fn func(string, string)) { w.callback = fn }

func (w *fakeWatcher) checkCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.checks
}

type certFixture struct {
	typ       string
	subject   *ec.PrivateKey
	certifier *ec.PrivateKey
	outpoint  *transaction.Outpoint
}

func newCertFixture(t *testing.T) certFixture {
	t.Helper()
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	return certFixture{
		typ: base64.StdEncoding.EncodeToString(bytesOf(1, 32)), subject: subject, certifier: certifier,
		outpoint: &transaction.Outpoint{Txid: chainhash.HashH([]byte("revocation output")), Index: 2},
	}
}

func bytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}
	return b
}

func (f certFixture) certificate(t *testing.T, subject *ec.PublicKey, outpoint *transaction.Outpoint) *certificates.VerifiableCertificate {
	t.Helper()
	cert := &certificates.Certificate{
		Type: wallet.StringBase64(f.typ), SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString(bytesOf(2, 32))),
		Subject: *subject, Certifier: *f.certifier.PubKey(), RevocationOutpoint: outpoint,
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	signer, err := wallet.NewCompletedProtoWallet(f.certifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(t.Context(), signer); err != nil {
		t.Fatal(err)
	}
	return certificates.NewVerifiableCertificate(cert, nil)
}

func (f certFixture) gate(t *testing.T, watch *fakeWatcher, alter func(*Config)) *Gate {
	t.Helper()
	cfg := Config{
		Certifiers: []string{hex.EncodeToString(f.certifier.PubKey().Compressed())}, Types: []string{f.typ},
		RevocationCheck: "strict", Recheck: time.Hour, Watcher: watch,
	}
	if alter != nil {
		alter(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestVerifierRules(t *testing.T) {
	f := newCertFixture(t)
	valid := func(t *testing.T) (*fakeWatcher, *Gate, *certificates.VerifiableCertificate) {
		w := newFakeWatcher()
		return w, f.gate(t, w, nil), f.certificate(t, f.subject.PubKey(), f.outpoint)
	}
	t.Run("valid", func(t *testing.T) {
		watch, gate, cert := valid(t)
		if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		if !watch.watched[f.outpoint.String()] {
			t.Fatal("reverification removed the revocation watch")
		}
		if !gate.Admitted(t.Context(), hex.EncodeToString(f.subject.PubKey().Compressed())) {
			t.Fatal("verified identity was not cached")
		}
	})
	t.Run("wrong certifier", func(t *testing.T) {
		w, _, cert := valid(t)
		other, _ := ec.NewPrivateKey()
		gate := f.gate(t, w, func(c *Config) { c.Certifiers = []string{hex.EncodeToString(other.PubKey().Compressed())} })
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
			t.Fatal("wrong certifier admitted")
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		w, _, cert := valid(t)
		otherType := base64.StdEncoding.EncodeToString(bytesOf(9, 32))
		gate := f.gate(t, w, func(c *Config) { c.Types = []string{otherType} })
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
			t.Fatal("wrong type admitted")
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		_, gate, cert := valid(t)
		cert.Signature[5] ^= 0xff
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
			t.Fatal("bad signature admitted")
		}
	})
	t.Run("subject mismatch", func(t *testing.T) {
		w := newFakeWatcher()
		signatureChecks := 0
		gate := f.gate(t, w, func(c *Config) {
			c.VerifySignature = func(ctx context.Context, cert *certificates.Certificate) error {
				signatureChecks++
				return cert.Verify(ctx)
			}
		})
		other, _ := ec.NewPrivateKey()
		cert := f.certificate(t, other.PubKey(), f.outpoint)
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
			t.Fatal("certificate for another subject admitted")
		}
		if signatureChecks != 0 {
			t.Fatalf("signature checks = %d, want 0", signatureChecks)
		}
	})
	t.Run("required field missing", func(t *testing.T) {
		w, _, cert := valid(t)
		gate := f.gate(t, w, func(c *Config) { c.RevealFields = map[string][]string{f.typ: {"role"}} })
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
			t.Fatal("missing required field admitted")
		}
	})
}

func TestVerifyAnyExaminesAtMostEightCertificates(t *testing.T) {
	f := newCertFixture(t)
	w := newFakeWatcher()
	gate := f.gate(t, w, nil)
	other, _ := ec.NewPrivateKey()
	bad := f.certificate(t, other.PubKey(), f.outpoint)
	certs := make([]*certificates.VerifiableCertificate, 8, 9)
	for i := range certs {
		copyCert := *bad
		certs[i] = &copyCert
	}
	certs = append(certs, f.certificate(t, f.subject.PubKey(), f.outpoint))
	if err := gate.VerifyAny(t.Context(), f.subject.PubKey(), certs); !errors.Is(err, ErrRefused) {
		t.Fatalf("VerifyAny error = %v, want refusal before ninth certificate", err)
	}
}

func TestVerifyAnyCountsOneRefusedDecision(t *testing.T) {
	f := newCertFixture(t)
	gate := f.gate(t, newFakeWatcher(), nil)
	other, _ := ec.NewPrivateKey()
	bad := f.certificate(t, other.PubKey(), f.outpoint)
	if err := gate.VerifyAny(t.Context(), f.subject.PubKey(), []*certificates.VerifiableCertificate{bad, bad}); err == nil {
		t.Fatal("invalid certificate set admitted")
	}
	if got := gate.Stats()["certgate_refused"]; got != 1 {
		t.Fatalf("certgate_refused = %d, want 1", got)
	}
}

func TestFreshAdmissionSkipsRevocationCheck(t *testing.T) {
	f := newCertFixture(t)
	w := newFakeWatcher()
	gate := f.gate(t, w, nil)
	cert := f.certificate(t, f.subject.PubKey(), f.outpoint)
	if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
		t.Fatal(err)
	}
	if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
		t.Fatal(err)
	}
	if got := w.checkCount(); got != 1 {
		t.Fatalf("revocation checks = %d, want 1", got)
	}
}

func TestRevocationPolicy(t *testing.T) {
	f := newCertFixture(t)
	sentinel := &transaction.Outpoint{}
	t.Run("sentinel refused by default", func(t *testing.T) {
		w := newFakeWatcher()
		gate := f.gate(t, w, nil)
		if gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), sentinel)) == nil {
			t.Fatal("sentinel admitted")
		}
	})
	t.Run("sentinel allowed by policy", func(t *testing.T) {
		w := newFakeWatcher()
		gate := f.gate(t, w, func(c *Config) { c.AllowUnrevocable = map[string]bool{f.typ: true} })
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), sentinel)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("spent refused", func(t *testing.T) {
		w := newFakeWatcher()
		w.spent = true
		gate := f.gate(t, w, nil)
		if gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)) == nil {
			t.Fatal("spent certificate admitted")
		}
	})
	t.Run("strict check error refused", func(t *testing.T) {
		w := newFakeWatcher()
		w.checkErr = errors.New("offline")
		gate := f.gate(t, w, nil)
		if gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)) == nil {
			t.Fatal("strict lookup error admitted")
		}
	})
	t.Run("lazy check error admitted for at most one minute", func(t *testing.T) {
		w := newFakeWatcher()
		w.checkErr = errors.New("offline")
		now := time.Unix(100, 0)
		gate := f.gate(t, w, func(c *Config) { c.RevocationCheck = "lazy"; c.Now = func() time.Time { return now } })
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)); err != nil {
			t.Fatal(err)
		}
		gate.mu.Lock()
		for _, adm := range gate.cache {
			if adm.expires.Sub(now) > time.Minute {
				t.Fatal("lazy retry exceeds one minute")
			}
		}
		gate.mu.Unlock()
	})
}

func TestCandidateSpendMustVerifyBeforeRevocation(t *testing.T) {
	f := newCertFixture(t)
	w := newFakeWatcher()
	gate := f.gate(t, w, nil)
	cert := f.certificate(t, f.subject.PubKey(), f.outpoint)
	if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
		t.Fatal(err)
	}
	identity := hex.EncodeToString(f.subject.PubKey().Compressed())
	revoked := make(chan string, 1)
	revokedToo := make(chan string, 1)
	gate.OnRevoke("test", func(id string) { revoked <- id })
	gate.OnRevoke("test-too", func(id string) { revokedToo <- id })
	gate.SetSpendVerifier(func(context.Context, string, string) error { return errors.New("forged") })
	w.callback(f.outpoint.String(), strings.Repeat("a", 64))
	time.Sleep(10 * time.Millisecond)
	if !gate.Admitted(t.Context(), identity) {
		t.Fatal("forged spend hint revoked admission")
	}
	gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
	w.callback(f.outpoint.String(), strings.Repeat("b", 64))
	select {
	case got := <-revoked:
		if got != identity {
			t.Fatalf("hook identity = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("verified spend did not revoke")
	}
	select {
	case got := <-revokedToo:
		if got != identity {
			t.Fatalf("second hook identity = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("verified spend did not notify every consumer")
	}
	if gate.Admitted(t.Context(), identity) {
		t.Fatal("revoked admission remained cached")
	}
}
