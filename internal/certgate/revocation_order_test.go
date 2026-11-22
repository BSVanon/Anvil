package certgate

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConfirmedSpendRemovesPinnedAdmissionBeforeHooks(t *testing.T) {
	f := newCertFixture(t)
	w := newFakeWatcher()
	gate := f.gate(t, w, nil)
	cert := f.certificate(t, f.subject.PubKey(), f.outpoint)
	if err := gate.Verify(t.Context(), f.subject.PubKey(), cert); err != nil {
		t.Fatal(err)
	}
	identity := hex.EncodeToString(f.subject.PubKey().Compressed())
	outpoint := f.outpoint.String()
	if _, err := gate.PinAdmission(identity, outpoint); err != nil {
		t.Fatal(err)
	}

	hookCalled := make(chan struct{}, 1)
	gate.OnRevoke("claim", func(got string) {
		if got != identity {
			t.Errorf("revoked identity = %q", got)
		}
		if gate.Admitted(t.Context(), identity) {
			t.Error("revocation hook observed an admitted identity")
		}
		if gate.AdmissionMatches(identity, outpoint) {
			t.Error("revocation hook observed a matching admission")
		}
		hookCalled <- struct{}{}
	})
	gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
	w.callback(outpoint, strings.Repeat("d", 64))
	select {
	case <-hookCalled:
	case <-time.After(time.Second):
		t.Fatal("confirmed spend did not run the revocation hook")
	}

	if gate.Admitted(t.Context(), identity) {
		t.Fatal("confirmed spend left the identity admitted")
	}
	if gate.AdmissionMatches(identity, outpoint) {
		t.Fatal("confirmed spend left a matching admission")
	}
	gate.mu.Lock()
	_, pinned := gate.pinned[identity]
	gate.mu.Unlock()
	if pinned {
		t.Fatal("confirmed spend left the admission pinned")
	}
	deadline := time.Now().Add(time.Second)
	var watched bool
	for time.Now().Before(deadline) {
		w.mu.Lock()
		watched = w.watched[outpoint]
		w.mu.Unlock()
		if !watched {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if watched {
		t.Fatal("confirmed spend left the outpoint watched")
	}
	if _, err := gate.PinAdmission(identity, outpoint); !errors.Is(err, ErrWatchUnavailable) {
		t.Fatalf("pin after confirmed spend = %v", err)
	}
}
