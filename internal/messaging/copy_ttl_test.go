package messaging

import (
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb/util"
)

func countExpiryKeys(t *testing.T, s *Store) int {
	t.Helper()
	iter := s.db.NewIterator(util.BytesPrefix(prefixExpiry), nil)
	defer iter.Release()
	n := 0
	for iter.Next() {
		n++
	}
	return n
}

// TestExpiryBaseForArithmetic pins expiryBaseFor's contract directly: it
// is the "ex:" key timestamp that makes ExpireOld's unmodified cutoff
// (now - ttlSeconds) fire exactly copyTTLSeconds after receivedAt. When
// copyTTLSeconds == ttlSeconds (every Send/Deliver call), the result is
// exactly receivedAt — the "no-op" case old records rely on.
func TestExpiryBaseForArithmetic(t *testing.T) {
	cases := []struct {
		name       string
		receivedAt int64
		copyTTL    int64
		ttl        int64
		want       int64
	}{
		{"copyTTL equals ttl_seconds is a no-op", 1000, 604800, 604800, 1000},
		{"copyTTL shorter than ttl_seconds", 1000, 86400, 604800, 1000 + 86400 - 604800},
		{"copyTTL longer than ttl_seconds", 1000, 604800, 86400, 1000 + 604800 - 86400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := expiryBaseFor(c.receivedAt, c.copyTTL, c.ttl); got != c.want {
				t.Fatalf("expiryBaseFor(%d,%d,%d) = %d, want %d", c.receivedAt, c.copyTTL, c.ttl, got, c.want)
			}
		})
	}
}

// TestDecodeRecordWithoutExpiryBaseFallsBackToReceivedAt pins the
// no-migration guarantee at the decode layer: JSON with no "expiryBase"
// field at all (every record written before this brick) decodes
// ExpiryBase to zero, and effectiveExpiryBase then falls back to
// ReceivedAt — exactly the timestamp that record's "ex:" key was
// originally written under.
func TestDecodeRecordWithoutExpiryBaseFallsBackToReceivedAt(t *testing.T) {
	raw := []byte(`{"messageId":"old-1","sender":"s","recipient":"r","messageBox":"box","body":"b","timestamp":1700000000,"senderAttestedBy":"sender","receivedAt":1700000000}`)
	record, err := decodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if record.ExpiryBase != 0 {
		t.Fatalf("ExpiryBase = %d, want 0 (absent from pre-brick JSON)", record.ExpiryBase)
	}
	if got := effectiveExpiryBase(record); got != record.ReceivedAt {
		t.Fatalf("effectiveExpiryBase = %d, want ReceivedAt %d", got, record.ReceivedAt)
	}
}

// TestDeliverCopyExpiresAtForwardCopyTTLWhileHomeKeepsStoreTTL is the
// spec's expiry test: "a forwarded copy expires at forward_copy_ttl, and
// a home copy at ttl_seconds." Both records sit in the same store with
// the same ReceivedAt; only DeliverCopy's record is due once the clock
// passes its shorter per-copy TTL.
func TestDeliverCopyExpiresAtForwardCopyTTLWhileHomeKeepsStoreTTL(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 604800}) // 7 days, the store-wide default
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	sender := testIdentity(t)
	homeRecipient, elsewhereRecipient := testIdentity(t), testIdentity(t)

	homeMsg := &Message{MessageID: "home-1", Sender: sender, Recipient: homeRecipient, MessageBox: "inbox", Body: "home copy"}
	if ok, err := s.Deliver(homeMsg, "sender"); err != nil || !ok {
		t.Fatalf("Deliver (home) = %v, %v", ok, err)
	}
	copyMsg := &Message{MessageID: "copy-1", Sender: sender, Recipient: elsewhereRecipient, MessageBox: "inbox", Body: "forwarded copy"}
	if ok, err := s.DeliverCopy(copyMsg, "sender", 86400); err != nil || !ok { // 24h forward_copy_ttl
		t.Fatalf("DeliverCopy = %v, %v", ok, err)
	}

	// Advance past the 24h copy TTL but nowhere near the 7-day store TTL.
	now = now.Add(25 * time.Hour)
	if expired := s.ExpireOld(); expired != 1 {
		t.Fatalf("expired = %d, want 1 (only the forwarded copy)", expired)
	}
	if msgs, err := s.List(homeRecipient, "inbox"); err != nil || len(msgs) != 1 {
		t.Fatalf("home copy should survive: msgs=%+v err=%v", msgs, err)
	}
	if msgs, err := s.List(elsewhereRecipient, "inbox"); err != nil || len(msgs) != 0 {
		t.Fatalf("forwarded copy should be gone: msgs=%+v err=%v", msgs, err)
	}

	// Advance past the 7-day store TTL: the home copy now expires too.
	now = now.Add(7 * 24 * time.Hour)
	if expired := s.ExpireOld(); expired != 1 {
		t.Fatalf("expired = %d, want 1 (the home copy, now past ttl_seconds)", expired)
	}
}

// TestSendElsewhereNotStoredWhenStoreFalse covers forward_copy_ttl == 0:
// the message is relayed (the API/gossip layers' job, not the store's)
// but never stored here, though SendElsewhere still mints and returns a
// MessageID so the caller's API response and gossip forward agree.
func TestSendElsewhereNotStoredWhenStoreFalse(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 604800})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	msg := &Message{Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "unstored"}
	id, err := s.SendElsewhere(msg, origin, 0, false)
	if err != nil {
		t.Fatalf("SendElsewhere: %v", err)
	}
	if id == "" {
		t.Fatal("expected a non-empty minted MessageID even when store=false")
	}
	if msgs, err := s.List(recipient, "inbox"); err != nil || len(msgs) != 0 {
		t.Fatalf("expected nothing stored: msgs=%+v err=%v", msgs, err)
	}
}

// TestSendElsewhereStoredAtCopyTTLWhenStoreTrue mirrors the DeliverCopy
// expiry test for the API-send ("Elsewhere", forward_copy_ttl > 0) row.
func TestSendElsewhereStoredAtCopyTTLWhenStoreTrue(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 604800})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	msg := &Message{Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "elsewhere copy"}
	id, err := s.SendElsewhere(msg, origin, 86400, true)
	if err != nil || id == "" {
		t.Fatalf("SendElsewhere = %q, %v", id, err)
	}
	if msgs, err := s.List(recipient, "inbox"); err != nil || len(msgs) != 1 {
		t.Fatalf("expected 1 stored copy: msgs=%+v err=%v", msgs, err)
	}

	now = now.Add(25 * time.Hour)
	if expired := s.ExpireOld(); expired != 1 {
		t.Fatalf("expired = %d, want 1 (past the 24h forward_copy_ttl)", expired)
	}
}

// TestAcknowledgeRemovesExpiryIndexEntryForPerCopyTTLRecord is the
// spec's "an acknowledgement deletes both index entries" test, run
// against a per-copy-TTL record specifically: deletePrimaryLocked must
// recompute the SAME "ex:" key DeliverCopy wrote (via effectiveExpiryBase),
// not the plain-ReceivedAt key a Home-row record would use. A wrong
// fallback leaves a stale "ex:" key behind, which this detects directly
// by counting them (not just trusting ExpireOld's self-healing scan).
func TestAcknowledgeRemovesExpiryIndexEntryForPerCopyTTLRecord(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 604800})
	sender, recipient := testIdentity(t), testIdentity(t)
	msg := &Message{MessageID: "copy-ack-1", Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "forwarded copy"}
	if ok, err := s.DeliverCopy(msg, "sender", 86400); err != nil || !ok {
		t.Fatalf("DeliverCopy = %v, %v", ok, err)
	}
	if n := countExpiryKeys(t, s); n != 1 {
		t.Fatalf("expiry index count before ack = %d, want 1", n)
	}

	deleted, err := s.Acknowledge(recipient, []string{"copy-ack-1"})
	if err != nil || deleted != 1 {
		t.Fatalf("Acknowledge = %d, %v", deleted, err)
	}
	if n := countExpiryKeys(t, s); n != 0 {
		t.Fatalf("expiry index count after ack = %d, want 0 (stale per-copy-TTL ex: key left behind)", n)
	}
}
