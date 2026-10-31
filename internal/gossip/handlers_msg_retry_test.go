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
	_, seen := mgr.msgSeen[dedup]
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
	mgr.msgSeen[dedup] = struct{}{}
	mgr.seenOwners = map[string]*forwardSeenOwner{dedup: newOwner}
	mgr.seenMu.Unlock()

	mgr.finishForwardSeen(dedup, oldOwner, true)
	mgr.seenMu.Lock()
	_, seen := mgr.msgSeen[dedup]
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

func TestEnvelopeSeenEvictionDoesNotRemoveInFlightForward(t *testing.T) {
	mgr := NewManager(ManagerConfig{Logger: slog.Default(), MaxSeen: 2})
	dedup := "msg:in-flight"
	mgr.seenMu.Lock()
	mgr.msgSeen[dedup] = struct{}{}
	mgr.seenOwners = map[string]*forwardSeenOwner{dedup: {}}
	mgr.seenMu.Unlock()

	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"type":"data","topic":"one","payload":"{}","timestamp":1}`),
		json.RawMessage(`{"type":"data","topic":"two","payload":"{}","timestamp":2}`),
		json.RawMessage(`{"type":"data","topic":"three","payload":"{}","timestamp":3}`),
	} {
		if err := mgr.onData("envelope-peer", raw); err != nil {
			t.Fatal(err)
		}
	}

	mgr.seenMu.Lock()
	_, seen := mgr.msgSeen[dedup]
	_, owned := mgr.seenOwners[dedup]
	mgr.seenMu.Unlock()
	if !seen || !owned {
		t.Fatalf("envelope eviction removed in-flight forward: seen=%v owned=%v", seen, owned)
	}
}

func TestMsgSeenEvictionSkipsOwnedEntries(t *testing.T) {
	t.Run("reclaims unowned entry", func(t *testing.T) {
		mgr := NewManager(ManagerConfig{Logger: slog.Default(), MaxSeen: 2})
		ownedKey := "msg:owned"
		unownedKey := "msg:unowned"
		mgr.seenMu.Lock()
		mgr.msgSeen[ownedKey] = struct{}{}
		mgr.msgSeen[unownedKey] = struct{}{}
		mgr.seenOwners = map[string]*forwardSeenOwner{ownedKey: {}}
		mgr.seenMu.Unlock()

		senderKey, sender := newID(t)
		_, recipient := newID(t)
		msg := sampleMsg(sender, recipient)
		msg.MessageID = "new"
		raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}

		mgr.seenMu.Lock()
		_, ownedSeen := mgr.msgSeen[ownedKey]
		_, unownedSeen := mgr.msgSeen[unownedKey]
		_, newSeen := mgr.msgSeen["msg:new"]
		gotLen := len(mgr.msgSeen)
		mgr.seenMu.Unlock()
		if !ownedSeen || unownedSeen || !newSeen || gotLen != 2 {
			t.Fatalf("msgSeen after eviction: owned=%v unowned=%v new=%v len=%d", ownedSeen, unownedSeen, newSeen, gotLen)
		}
	})

	t.Run("admits when every entry is owned", func(t *testing.T) {
		mgr := NewManager(ManagerConfig{Logger: slog.Default(), MaxSeen: 2})
		firstKey := "msg:first-owned"
		secondKey := "msg:second-owned"
		firstOwner := &forwardSeenOwner{}
		secondOwner := &forwardSeenOwner{}
		mgr.seenMu.Lock()
		mgr.msgSeen[firstKey] = struct{}{}
		mgr.msgSeen[secondKey] = struct{}{}
		mgr.seenOwners = map[string]*forwardSeenOwner{
			firstKey:  firstOwner,
			secondKey: secondOwner,
		}
		mgr.seenMu.Unlock()

		senderKey, sender := newID(t)
		_, recipient := newID(t)
		msg := sampleMsg(sender, recipient)
		msg.MessageID = "overflow"
		raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}

		mgr.seenMu.Lock()
		_, firstSeen := mgr.msgSeen[firstKey]
		_, secondSeen := mgr.msgSeen[secondKey]
		_, newSeen := mgr.msgSeen["msg:overflow"]
		gotLen := len(mgr.msgSeen)
		mgr.seenMu.Unlock()
		if !firstSeen || !secondSeen || !newSeen || gotLen != 3 {
			t.Fatalf("msgSeen owned admission: first=%v second=%v new=%v len=%d", firstSeen, secondSeen, newSeen, gotLen)
		}

		mgr.finishForwardSeen(firstKey, firstOwner, false)
		mgr.finishForwardSeen(secondKey, secondOwner, false)
		mgr.seenMu.Lock()
		gotLen = len(mgr.msgSeen)
		mgr.seenMu.Unlock()
		if gotLen > mgr.maxSeen {
			t.Fatalf("msgSeen remained over capacity after owners finished: len=%d cap=%d", gotLen, mgr.maxSeen)
		}
	})
}
