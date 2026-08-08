package topics

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// captureHandler is a minimal slog.Handler that records every emitted
// record so a test can assert on level, message, and attributes. It
// enables all levels so Debug skip lines are captured.
type captureHandler struct {
	mu      sync.Mutex
	records *[]slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func captureLogger() (*slog.Logger, *[]slog.Record) {
	var recs []slog.Record
	return slog.New(&captureHandler{records: &recs}), &recs
}

// findRecord returns the first captured record at the given level whose
// message equals msg, plus its attributes as a map, and whether it was
// found.
func findRecord(recs []slog.Record, level slog.Level, msg string) (map[string]string, bool) {
	for _, r := range recs {
		if r.Level != level || r.Message != msg {
			continue
		}
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		return attrs, true
	}
	return nil, false
}

const (
	msgSkip    = "overlay: skipped output during topic admission"
	msgNothing = "overlay: no outputs admitted and no previous coins consumed"
)

// TestAdmitLogging_KVStoreSignatureFailure is the reported-dev scenario:
// a KVStore-shaped token whose signature does not verify is skipped
// (HTTP contract unchanged — nothing admitted), and BOTH the per-output
// Debug skip reason and the Warn no-op-admit are now logged, matching the
// canonical KVStoreTopicManager console.debug/console.warn narration that
// Anvil previously dropped.
func TestAdmitLogging_KVStoreSignatureFailure(t *testing.T) {
	w, _ := kvControllerWallet(t)
	_, otherCtrl := kvControllerWallet(t) // controller field belongs to a different identity → sig fails
	scriptBytes := buildKVScript(t, w, otherCtrl, "fiat-currency", "GBP", nil, false)

	logger, recs := captureLogger()
	m := NewKVStoreTopicManager(WithLogger(logger))

	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected no admission (contract unchanged), got %+v", inst)
	}

	attrs, ok := findRecord(*recs, slog.LevelDebug, msgSkip)
	if !ok {
		t.Fatalf("expected a Debug skip record; got %d records: %+v", len(*recs), *recs)
	}
	if attrs["topic"] != KVStoreTopicName {
		t.Fatalf("skip topic = %q, want %q", attrs["topic"], KVStoreTopicName)
	}
	if attrs["output"] != "0" {
		t.Fatalf("skip output = %q, want 0", attrs["output"])
	}
	if !strings.Contains(attrs["reason"], "signature verification failed") {
		t.Fatalf("skip reason = %q, want it to name the signature failure", attrs["reason"])
	}

	if _, ok := findRecord(*recs, slog.LevelWarn, msgNothing); !ok {
		t.Fatalf("expected a Warn no-op-admit record; got: %+v", *recs)
	}
}

// TestAdmitLogging_HappyPathIsQuiet proves the logging adds no noise on a
// valid admission: a good token emits neither a skip nor a no-op-admit
// record.
func TestAdmitLogging_HappyPathIsQuiet(t *testing.T) {
	w, ctrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, ctrl, "fiat-currency", "GBP", []string{"prefs"}, true)

	logger, recs := captureLogger()
	m := NewKVStoreTopicManager(WithLogger(logger))

	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected output admitted, got %+v", inst)
	}
	if _, ok := findRecord(*recs, slog.LevelDebug, msgSkip); ok {
		t.Fatalf("valid admission must not log a skip; got: %+v", *recs)
	}
	if _, ok := findRecord(*recs, slog.LevelWarn, msgNothing); ok {
		t.Fatalf("valid admission must not log a no-op-admit; got: %+v", *recs)
	}
}

// TestAdmitLogging_NilLoggerSilentNoPanic confirms the zero-arg
// constructor (no logger) keeps the prior silent behavior and never
// panics on the skip path.
func TestAdmitLogging_NilLoggerSilentNoPanic(t *testing.T) {
	w, _ := kvControllerWallet(t)
	_, otherCtrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, otherCtrl, "k", "v", nil, false)

	m := NewKVStoreTopicManager() // no WithLogger → silent
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected no admission, got %+v", inst)
	}
}

// TestAdmitLogging_UHRPMalformedHash exercises the shared skip path on a
// non-signature topic: a UHRP-tagged OP_RETURN whose content-hash field
// is the wrong length is skipped with a logged reason, while a plain
// non-UHRP output stays silent.
func TestAdmitLogging_UHRPMalformedHash(t *testing.T) {
	// OP_FALSE OP_RETURN "UHRP" <10-byte hash> — UHRP-tagged but the hash
	// field is neither 32 raw nor 64 hex, so it is malformed.
	badHash := []byte("0123456789") // 10 bytes
	script := []byte{0x00, 0x6a, 0x04, 'U', 'H', 'R', 'P', byte(len(badHash))}
	script = append(script, badHash...)

	logger, recs := captureLogger()
	u := NewUHRPTopicManager(WithLogger(logger))

	if _, err := u.Admit(txWith(t, script), nil); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	attrs, ok := findRecord(*recs, slog.LevelDebug, msgSkip)
	if !ok {
		t.Fatalf("expected a Debug skip record for malformed UHRP hash; got: %+v", *recs)
	}
	if attrs["topic"] != UHRPTopicName {
		t.Fatalf("skip topic = %q, want %q", attrs["topic"], UHRPTopicName)
	}
	if !strings.Contains(attrs["reason"], "content-hash length") {
		t.Fatalf("skip reason = %q, want it to name the bad hash length", attrs["reason"])
	}
}
