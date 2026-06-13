package overlayctx

import (
	"context"
	"testing"
)

func TestTopicCommitNotifier_RoundTrip(t *testing.T) {
	var got []string
	ctx := WithTopicCommitNotifier(context.Background(), func(topic string) {
		got = append(got, topic)
	})
	NotifyTopicCommitted(ctx, "tm_a")
	NotifyTopicCommitted(ctx, "tm_b")
	NotifyTopicCommitted(ctx, "tm_a")
	if len(got) != 3 {
		t.Fatalf("notifier should fire each call, got %d", len(got))
	}
	if got[0] != "tm_a" || got[1] != "tm_b" || got[2] != "tm_a" {
		t.Fatalf("notifier should receive the topic name per call, got %v", got)
	}
}

func TestTopicCommitNotifier_NoNotifierIsNoop(t *testing.T) {
	// No panic, no-op when no notifier was registered (the normal path for GASP
	// sync / internalize and any non-legacy-submit caller).
	NotifyTopicCommitted(context.Background(), "tm_a")
}

func TestTopicCommitNotifier_NilNotifierUnchanged(t *testing.T) {
	ctx := WithTopicCommitNotifier(context.Background(), nil)
	if ctx != context.Background() {
		t.Fatal("nil notifier must return the context unchanged")
	}
	NotifyTopicCommitted(ctx, "tm_a") // no panic
}
