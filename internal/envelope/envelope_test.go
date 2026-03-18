package envelope

import (
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func testKey() *ec.PrivateKey {
	key, _ := ec.PrivateKeyFromWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S")
	return key
}

func validEnvelope(t *testing.T) *Envelope {
	t.Helper()
	env := &Envelope{
		Type:      "data",
		Topic:     "test:topic",
		Payload:   "test payload data",
		TTL:       300,
		Timestamp: 1710000000,
	}
	env.Sign(testKey())
	return env
}

func validDurableEnvelope(t *testing.T) *Envelope {
	t.Helper()
	env := &Envelope{
		Type:      "data",
		Topic:     "app:sessions:test",
		Payload:   "durable session data",
		TTL:       0,
		Durable:   true,
		Timestamp: 1710000000,
	}
	env.Sign(testKey())
	return env
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

func TestValidateRejectsTTL0WithoutDurable(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 0
	env.Durable = false
	if err := env.Validate(); err == nil {
		t.Fatal("expected error for TTL=0 without durable=true")
	}
}

// --- Tamper tests: changing any semantic field breaks the signature ---

func TestTamperPayload(t *testing.T) {
	env := validEnvelope(t)
	env.Payload = "tampered payload"
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after payload tamper")
	}
}

func TestTamperTopic(t *testing.T) {
	env := validEnvelope(t)
	env.Topic = "evil:topic"
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after topic tamper")
	}
}

func TestTamperTTL(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 9999
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after TTL tamper")
	}
}

func TestTamperDurable(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 0
	env.Durable = true // was false with TTL=300
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after durable tamper")
	}
}

func TestTamperTimestamp(t *testing.T) {
	env := validEnvelope(t)
	env.Timestamp = 9999999999
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after timestamp tamper")
	}
}

func TestTamperType(t *testing.T) {
	env := validEnvelope(t)
	env.Type = "evil"
	if err := env.Validate(); err == nil {
		t.Fatal("expected signature failure after type tamper")
	}
}

// --- Expiration ---

func TestIsExpiredEphemeral(t *testing.T) {
	env := validEnvelope(t)
	env.TTL = 1
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
	env.ReceivedAt = time.Now().Add(-365 * 24 * time.Hour)
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
	if !results[0].Durable {
		t.Fatal("expected durable=true")
	}
}

func TestIngestRejectsInvalidEnvelope(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := &Envelope{Topic: "", Payload: "x"}
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestIngestRejectsOversizeDurable(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := &Envelope{
		Type:      "data",
		Topic:     "big:topic",
		Payload:   string(make([]byte, 100000)),
		TTL:       0,
		Durable:   true,
		Timestamp: 1710000000,
	}
	env.Sign(testKey())
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection for oversize durable")
	}
}

func TestIngestRejectsExcessiveTTL(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := &Envelope{
		Type:      "data",
		Topic:     "ttl:topic",
		Payload:   "data",
		TTL:       99999,
		Timestamp: 1710000000,
	}
	env.Sign(testKey())
	if err := s.Ingest(env); err == nil {
		t.Fatal("expected rejection for excessive TTL")
	}
}

func TestExpireEphemeralRemovesOld(t *testing.T) {
	s := tmpEnvelopeStore(t)
	env := &Envelope{
		Type:      "data",
		Topic:     "expire:test",
		Payload:   "will expire",
		TTL:       1,
		Timestamp: 1710000000,
	}
	env.Sign(testKey())
	if err := s.Ingest(env); err != nil {
		t.Fatal(err)
	}

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
	// Re-validate after round-trip — signature must still verify
	if err := env2.Validate(); err != nil {
		t.Fatalf("signature invalid after round-trip: %v", err)
	}
}

// --- SigningDigest determinism ---

func TestSigningDigestDeterministic(t *testing.T) {
	env := validEnvelope(t)
	d1 := env.SigningDigest()
	d2 := env.SigningDigest()
	if d1 != d2 {
		t.Fatal("signing digest not deterministic")
	}
}
