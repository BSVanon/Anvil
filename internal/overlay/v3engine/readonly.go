package v3engine

import (
	"context"
	"net/http"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// readOnly is r's context marked overlayctx.ReadOnly: the context of a lookup
// or a GASP reply, which writes nothing, so the engine's storage reads for it
// stop when its client goes away (detached.go).
func readOnly(r *http.Request) context.Context { return overlayctx.ReadOnly(r.Context()) }

// lookupFor runs eng's lookup of question for r under readOnly(r), and fails
// with r's context's error when r's client went away before it ended, so that
// the handler does not aggregate an answer nobody will read.
func lookupFor(r *http.Request, eng *engine.Engine, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	result, err := boundedLookupFor(r, eng, question, 0)
	return result.Answer, err
}

func boundedLookupFor(r *http.Request, eng *engine.Engine, question *lookup.LookupQuestion, cursor int) (lookupguard.Result, error) {
	return boundedLookupForWire(r, eng, question, cursor, false)
}

func boundedLookupForWire(r *http.Request, eng *engine.Engine, question *lookup.LookupQuestion, cursor int, binary bool) (lookupguard.Result, error) {
	result, err := lookupguard.LookupForWire(readOnly(r), eng, question, cursor, binary)
	if err == nil && r.Context().Err() != nil {
		return lookupguard.Result{}, r.Context().Err()
	}
	return result, err
}
