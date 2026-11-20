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

// cancelingLookupEngine is a scriptedEngine whose Lookup cancels the
// request's own context, simulating the client going away mid-lookup,
// before returning an answer.
type cancelingLookupEngine struct {
	scriptedEngine
	cancel func()
}

func (e *cancelingLookupEngine) Lookup(ctx context.Context, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	e.cancel()
	return &lookup.LookupAnswer{}, nil
}

// TestQuery_ClientGoneBeforeTheAnswer (cold review round 4 nit, "no
// client-gone check before canonicalToLegacyAnswer", legacyshim/routes.go):
// when the client left while the engine's lookup ran, /overlay/query must
// not go on to hydrate a legacy answer, the Metadata field rebuilt from the
// BEEF the canonical engine hydrated among it, for nobody.
func TestQuery_ClientGoneBeforeTheAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	req, w := queryReq()
	req = req.WithContext(ctx)
	eng := &cancelingLookupEngine{cancel: cancel}
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}
	shim.Query(w, req)
	if w.Body.Len() != 0 {
		t.Fatalf("/overlay/query with the client gone before the answer wrote %d bytes (%q), want none: no hydration for nobody", w.Body.Len(), w.Body.String())
	}
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
