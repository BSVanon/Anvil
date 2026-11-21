package certgate

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestAdmissionCacheProperties(t *testing.T) {
	f := newCertFixture(t)
	now := time.Unix(1_000, 0)
	w := newFakeWatcher()
	signatures := 0
	gate := f.gate(t, w, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.VerifySignature = func(context.Context, *certificates.Certificate) error {
			signatures++
			return nil
		}
	})
	cert := f.certificate(t, f.subject.PubKey(), f.outpoint)
	if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
		t.Fatal(err)
	}

	t.Run("identity isolation", func(t *testing.T) {
		other, _ := ec.NewPrivateKey()
		if gate.Admitted(t.Context(), hex.EncodeToString(other.PubKey().Compressed())) {
			t.Fatal("one identity's admission admitted another identity")
		}
	})

	t.Run("eviction requires full verification", func(t *testing.T) {
		for i := 0; i < maxAdmissions; i++ {
			gate.remember(cacheKey{identity: fmt.Sprintf("identity-%05d", i), typ: f.typ}, "", now.Add(time.Hour))
		}
		gate.mu.Lock()
		entries := len(gate.cache)
		gate.mu.Unlock()
		if entries > maxAdmissions {
			t.Fatalf("cache entries = %d, limit %d", entries, maxAdmissions)
		}
		if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		if signatures != 2 || w.checkCount() != 2 {
			t.Fatalf("after eviction: signature checks %d, revocation checks %d; want 2, 2", signatures, w.checkCount())
		}
	})

	t.Run("expiry requires full verification", func(t *testing.T) {
		expiryWatch := newFakeWatcher()
		expirySignatures := 0
		expiryGate := f.gate(t, expiryWatch, func(c *Config) {
			c.Now = func() time.Time { return now }
			c.VerifySignature = func(context.Context, *certificates.Certificate) error {
				expirySignatures++
				return nil
			}
		})
		if err := expiryGate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Hour)
		if err := expiryGate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		if expirySignatures != 2 || expiryWatch.checkCount() != 2 {
			t.Fatalf("after expiry: signature checks %d, revocation checks %d; want 2, 2", expirySignatures, expiryWatch.checkCount())
		}
	})
}

func TestRevocationLookupProperties(t *testing.T) {
	f := newCertFixture(t)
	cert := f.certificate(t, f.subject.PubKey(), f.outpoint)
	identity := hex.EncodeToString(f.subject.PubKey().Compressed())

	t.Run("lazy retries within one minute", func(t *testing.T) {
		now := time.Unix(5_000, 0)
		w := newFakeWatcher()
		w.checkErr = errors.New("lookup failed")
		gate := f.gate(t, w, func(c *Config) {
			c.RevocationCheck = "lazy"
			c.Now = func() time.Time { return now }
		})
		if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
			t.Fatal(err)
		}
		if !gate.Admitted(t.Context(), identity) || w.checkCount() != 1 {
			t.Fatal("fresh lazy admission did not remain admitted")
		}
		now = now.Add(time.Minute)
		if !gate.Admitted(t.Context(), identity) || w.checkCount() != 2 {
			t.Fatalf("lazy admission did not retry at one minute; checks = %d", w.checkCount())
		}
	})

	t.Run("strict refuses lookup errors", func(t *testing.T) {
		w := newFakeWatcher()
		w.checkErr = errors.New("lookup failed")
		gate := f.gate(t, w, nil)
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil || gate.Admitted(t.Context(), identity) {
			t.Fatal("strict lookup error admitted the certificate")
		}
	})

	t.Run("watch capacity is mandatory", func(t *testing.T) {
		w := newFakeWatcher()
		w.watchErr = errors.New("watch capacity reached")
		gate := f.gate(t, w, nil)
		if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil || gate.Admitted(t.Context(), identity) {
			t.Fatal("certificate was admitted without a revocation watch")
		}
	})
}

func TestVerificationWorkBounds(t *testing.T) {
	f := newCertFixture(t)
	w := newFakeWatcher()
	signatures := 0
	gate := f.gate(t, w, func(c *Config) {
		c.VerifySignature = func(context.Context, *certificates.Certificate) error {
			signatures++
			return nil
		}
	})
	valid := f.certificate(t, f.subject.PubKey(), f.outpoint)

	t.Run("policy mismatches skip signatures", func(t *testing.T) {
		other, _ := ec.NewPrivateKey()
		wrongType := *valid
		wrongType.Type = wallet.StringBase64(base64.StdEncoding.EncodeToString(bytesOf(9, 32)))
		wrongCertifier := *valid
		wrongCertifier.Certifier = *other.PubKey()
		wrongSubject := *valid
		wrongSubject.Subject = *other.PubKey()
		for name, cert := range map[string]*certificates.VerifiableCertificate{
			"type": &wrongType, "certifier": &wrongCertifier, "subject": &wrongSubject,
		} {
			t.Run(name, func(t *testing.T) {
				before := signatures
				if gate.Verify(t.Context(), f.subject.PubKey(), cert) == nil {
					t.Fatal("policy mismatch was admitted")
				}
				if signatures != before {
					t.Fatal("policy mismatch reached signature verification")
				}
			})
		}
	})

	t.Run("eight certificate maximum", func(t *testing.T) {
		other, _ := ec.NewPrivateKey()
		bad := f.certificate(t, other.PubKey(), f.outpoint)
		presented := make([]*certificates.VerifiableCertificate, 9)
		for i := range 8 {
			copyCert := *bad
			presented[i] = &copyCert
		}
		presented[8] = valid
		if !errors.Is(gate.VerifyAny(t.Context(), f.subject.PubKey(), presented), ErrRefused) {
			t.Fatal("VerifyAny examined a ninth certificate")
		}
	})

	t.Run("repeated admission uses one network check", func(t *testing.T) {
		for range 1_000 {
			if err := gate.Verify(t.Context(), f.subject.PubKey(), valid); err != nil {
				t.Fatal(err)
			}
		}
		if got := w.checkCount(); got != 1 {
			t.Fatalf("network revocation checks = %d, want 1", got)
		}
	})
}
