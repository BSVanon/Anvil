package storage

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"

	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
)

// TestAppliedTransaction_FiresTopicCommitNotifier locks the v3.2.1 durable-commit
// wiring the legacy /overlay/submit handler depends on: Storage must fire the
// per-topic commit notifier (a) when a topic is newly applied
// (InsertAppliedTransaction — the engine's final per-topic commit step) and
// (b) when a topic is ALREADY applied from a prior submit
// (DoesAppliedTransactionExist returns true — the dupe/re-submit path that makes
// a client retry ack fast instead of re-hanging). It must NOT fire for a topic
// that has never been applied. Exercises the real LevelDB-backed Storage, not a
// mock.
func TestAppliedTransaction_FiresTopicCommitNotifier(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x42)
	applied := &overlay.AppliedTransaction{Txid: txid, Topic: topicA}

	var fired []string
	ctx := overlayctx.WithTopicCommitNotifier(context.Background(), func(topic string) {
		fired = append(fired, topic)
	})

	// (a) Newly durable: InsertAppliedTransaction fires once for its topic.
	if err := s.InsertAppliedTransaction(ctx, applied); err != nil {
		t.Fatalf("insert applied: %v", err)
	}
	if len(fired) != 1 || fired[0] != topicA {
		t.Fatalf("InsertAppliedTransaction must fire the notifier once for %q, got %v", topicA, fired)
	}

	// (b) Already durable (dupe re-submit): DoesAppliedTransactionExist returns
	// true and fires the notifier for that topic.
	fired = nil
	exists, err := s.DoesAppliedTransactionExist(ctx, applied)
	if err != nil {
		t.Fatalf("does-applied-exist: %v", err)
	}
	if !exists {
		t.Fatal("expected applied tx to exist after insert")
	}
	if len(fired) != 1 || fired[0] != topicA {
		t.Fatalf("DoesAppliedTransactionExist(dupe) must fire the notifier for %q, got %v", topicA, fired)
	}

	// (c) Never applied: same txid, different topic — must NOT fire (no durable
	// commit to report, so the handler keeps waiting / falls through to the
	// engine's authoritative result).
	fired = nil
	exists, err = s.DoesAppliedTransactionExist(ctx, &overlay.AppliedTransaction{Txid: txid, Topic: topicB})
	if err != nil {
		t.Fatalf("does-applied-exist (unapplied topic): %v", err)
	}
	if exists {
		t.Fatalf("expected (txid, %q) to be unapplied", topicB)
	}
	if len(fired) != 0 {
		t.Fatalf("an unapplied (txid, topic) must NOT fire the notifier, got %v", fired)
	}
}

// TestAppliedTransaction_NoNotifierIsHarmless confirms the Storage methods work
// normally when no notifier is registered on the context — the path taken by
// GASP sync, internalize, and every non-legacy-submit caller.
func TestAppliedTransaction_NoNotifierIsHarmless(t *testing.T) {
	s, _ := newStore(t)
	applied := &overlay.AppliedTransaction{Txid: makeHash(0x43), Topic: topicA}

	if err := s.InsertAppliedTransaction(context.Background(), applied); err != nil {
		t.Fatalf("insert applied (no notifier): %v", err)
	}
	exists, err := s.DoesAppliedTransactionExist(context.Background(), applied)
	if err != nil || !exists {
		t.Fatalf("does-applied-exist (no notifier): exists=%v err=%v", exists, err)
	}
}
