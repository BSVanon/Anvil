package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// testKey returns a deterministic private key for testing.
func testKey() *secp256k1.PrivateKey {
	b, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000003")
	return secp256k1.PrivKeyFromBytes(b)
}

// signPayload signs a payload with the given key, returns DER hex signature.
func signPayload(key *secp256k1.PrivateKey, payload string) string {
	hash := sha256.Sum256([]byte(payload))
	sig := ecdsa.Sign(key, hash[:])
	return hex.EncodeToString(sig.Serialize())
}

func validEnvelope(t *testing.T) *Envelope {
	t.Helper()
	key := testKey()
	payload := "test payload data"
	return &Envelope{
		Type:      "data",
		Topic:     "test:topic",
		Payload:   payload,
		Signature: signPayload(key, payload),
		Pubkey:    hex.EncodeToString(key.PubKey().SerializeCompressed()),
		TTL:       300,
	}
}

func validDurableEnvelope(t *testing.T) *Envelope {
	t.Helper()
	key := testKey()
	payload := "durable session data"
	return &Envelope{
		Type:      "data",
		Topic:     "app:sessions:test",
		Payload:   payload,
		Signature: signPayload(key, payload),
		Pubkey:    hex.EncodeToString(key.PubKey().SerializeCompressed()),
		TTL:       0,
		Durable:   true,
	}
}

// --- Envelope validation ---

func TestValidateGoodEnvelope(t *testing.T) {
	env := validEnvelope(t)
	if err := env.Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestValidateDurableEnvelope(t *testing.T) {
	env := validDurableEnvelope(t)
	if err := env.Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestValidateRejectsEmptyTopic(t *testing.T) {
	env := validEnvelope(t)
	env.Topic = ""
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for empty topic")
	}
}

func TestValidateRejectsEmptyPayload(t *testing.T) {
	env := validEnvelope(t)
	env.Payload = ""
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestValidateRejectsEmptySignature(t *testing.T) {
	env := validEnvelope(t)
	env.Signature = ""
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestValidateRejectsBadSignature(t *testing.T) {
	env := validEnvelope(t)
	// Sign a different payload
	env.Signature = signPayload(testKey(), "different payload")
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for signature mismatch")
	}
}

func TestValidateRejectsTTL0WithoutDurable(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 0
	env.Durable = false
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for TTL=0 without durable=true")
	}
}

// --- Expiration ---

func TestIsExpiredEphemeral(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 1 // 1 second
	env.ReceivedAt = time.Now().Add(-2 * time.Second)
	if !env.IsExpired() {
		t.Fatal("expected expired")
	}
}

func TestIsNotExpiredEphemeral(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 300
	env.ReceivedAt = time.Now()
	if env.IsExpired() {
		t.Fatal("expected not expired")
	}
}

func TestDurableNeverExpires(t *testing.T) {
	env := validDurableEnvelope(t)
	env.ReceivedAt = time.Now().Add(-365 * 24 * time.Hour) // 1 year ago
	if env.IsExpired() {
		t.Fatal("durable envelopes should never expire")
	}
}

// --- Store ---

func tmpEnvelopeStore(t *testing.T) *Store {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-envelope-test-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	s, err := NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestIngestAndQueryEphemeral(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := validEnvelope(t)

	if err := s.Ingest(env); err != nil {
		t.Fatal(err)
	}

	results, err := s.QueryByTopic("test:topic", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Payload != env.Payload {
		t.Fatalf("payload mismatch")
	}
}

func TestIngestAndQueryDurable(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := validDurableEnvelope(t)

	if err := s.Ingest(env); err != nil {
		t.Fatal(err)
	}

	results, err := s.QueryByTopic("app:sessions:test", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Durable != true {
		t.Fatal("expected durable=true")
	}
}

func TestIngestRejectsInvalidEnvelope(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := &Envelope{Topic: "", Payload: "x"} // invalid
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestIngestRejectsOversizeDurable(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := validDurableEnvelope(t)
	env.Payload = string(make([]byte, 100000)) // exceeds 65536 limit
	// Re-sign with the large payload
	env.Signature = signPayload(testKey(), env.Payload)
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection for oversize durable")
	}
}

func TestIngestRejectsExcessiveTTL(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := validEnvelope(t)
	env.TTL = 99999 // exceeds 3600 limit
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection for excessive TTL")
	}
}

func TestExpireEphemeralRemovesOld(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := validEnvelope(t)
	env.TTL = 1
	s.Ingest(env)

	// Manually backdate
	s.mu.Lock()
	for _, e := range s.ephemeral {
		e.ReceivedAt = time.Now().Add(-5 * time.Second)
	}
	s.mu.Unlock()

	expired := s.ExpireEphemeral()
	if expired != 1 {
		t.Fatalf("expected 1 expired, got %d", expired)
	}
	if s.CountEphemeral() != 0 {
		t.Fatal("expected 0 ephemeral after expiration")
	}
}

func TestQueryByTopicNoResults(t *testing.T) {
	s := tmpEnvelopeStore(t)
	results, err := s.QueryByTopic("nonexistent:topic", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// --- Marshal/Unmarshal ---

func TestMarshalRoundTrip(t *testing.T) {
	env := validEnvelope(t)
	data, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	env2, err := UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if env2.Topic != env.Topic || env2.Payload != env.Payload {
		t.Fatal("round-trip mismatch")
	}
}
