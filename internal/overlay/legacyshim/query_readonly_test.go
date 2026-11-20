package legacyshim

import (
	"context"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// readOnlyLookupEngine is a scriptedEngine whose Lookup notes whether its
// context was marked overlayctx.ReadOnly.
type readOnlyLookupEngine struct {
	scriptedEngine
	marked bool
}

func (e *readOnlyLookupEngine) Lookup(ctx context.Context, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	e.marked = overlayctx.IsReadOnly(ctx)
	return nil, nil
}

// TestQuery_LookupIsReadOnly (cold review round 3 S4): /overlay/query hands
// the engine its request's context marked overlayctx.ReadOnly, so the
// engine's storage reads for the query stop when its client goes away, as
// the canonical /lookup's do.
func TestQuery_LookupIsReadOnly(t *testing.T) {
	eng := &readOnlyLookupEngine{}
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}
	req, w := queryReq()
	shim.Query(w, req)
	if w.Code != http.StatusOK || !eng.marked {
		t.Fatalf("/overlay/query answered %d, engine context read-only %v; want 200 and read-only", w.Code, eng.marked)
	}
}
