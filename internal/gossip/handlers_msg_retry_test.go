package gossip

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/BSVanon/Anvil/internal/messaging"
)

func TestMsgForwardTransientStoreErrorCanBeRetried(t *testing.T) {
	failingStore, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := failingStore.Close(); err != nil {
		t.Fatal(err)
	}

	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(failingStore)
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "transient-store-failure"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 0 {
		t.Fatalf("failed forward relays = %d, want 0", *relays)
	}
	dedup := "msg:" + msg.MessageID
	mgr.seenMu.Lock()
	_, seen := mgr.seen[dedup]
	mgr.seenMu.Unlock()
	if seen {
		t.Fatal("failed forward remained in the seen map")
	}

	recoveredStore, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recoveredStore.Close() })
	mgr.SetMsgStore(recoveredStore)
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	got, err := recoveredStore.List(recipient, msg.MessageBox)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MessageID != msg.MessageID {
		t.Fatalf("retried delivery = %+v, want message %q", got, msg.MessageID)
	}
	if *relays != 1 {
		t.Fatalf("retried forward relays = %d, want 1", *relays)
	}
}

func TestFinishForwardSeenDoesNotClearNewerEntry(t *testing.T) {
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	dedup := "msg:replacement"
	oldOwner := &forwardSeenOwner{}
	newOwner := &forwardSeenOwner{}
	mgr.seenMu.Lock()
	mgr.seen[dedup] = struct{}{}
	mgr.seenOwners = map[string]*forwardSeenOwner{dedup: newOwner}
	mgr.seenMu.Unlock()

	mgr.finishForwardSeen(dedup, oldOwner, true)
	mgr.seenMu.Lock()
	_, seen := mgr.seen[dedup]
	mgr.seenMu.Unlock()
	if !seen {
		t.Fatal("older failed delivery cleared a newer seen entry")
	}

	mgr.finishForwardSeen(dedup, newOwner, false)
	mgr.seenMu.Lock()
	_, owned := mgr.seenOwners[dedup]
	mgr.seenMu.Unlock()
	if owned {
		t.Fatal("finished forward left its seen owner entry behind")
	}
}
