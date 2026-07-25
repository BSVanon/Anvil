package v3engine

import (
	"context"
	"errors"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/health"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// fakeLookup implements just enough of engine.LookupService for the wrapper
// test — only OutputAdmittedByTopic is exercised.
type fakeLookup struct {
	engine.LookupService // nil embedded; other methods are never called here
	err                  error
}

func (f fakeLookup) OutputAdmittedByTopic(_ context.Context, _ *engine.OutputAdmittedByTopic) error {
	return f.err
}

// A lookup-notify failure must be recorded in the health registry (keyed by
// topic) and still propagate; a success must record nothing. This is the
// mechanism that turns a silent indexing failure (the V1-BEEF bug) into
// something /status + `anvil doctor` surface.
func TestCountingLookupRecordsErrors(t *testing.T) {
	reg := health.New()

	failing := countingLookup{LookupService: fakeLookup{err: errors.New("kvstore lookup: parse beef: boom")}, reg: reg}
	err := failing.OutputAdmittedByTopic(context.Background(), &engine.OutputAdmittedByTopic{Topic: "tm_kvstore"})
	if err == nil {
		t.Fatal("wrapper must propagate the lookup error")
	}
	s := reg.Snapshot()
	if s.Total != 1 || s.ByTopic["tm_kvstore"].Total != 1 {
		t.Fatalf("expected 1 recorded error for tm_kvstore, got %+v", s)
	}

	ok := countingLookup{LookupService: fakeLookup{err: nil}, reg: reg}
	if err := ok.OutputAdmittedByTopic(context.Background(), &engine.OutputAdmittedByTopic{Topic: "tm_kvstore"}); err != nil {
		t.Fatalf("success path should not error: %v", err)
	}
	if s := reg.Snapshot(); s.Total != 1 {
		t.Fatalf("a successful notify must record nothing; total should stay 1, got %d", s.Total)
	}
}
