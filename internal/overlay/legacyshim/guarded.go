package legacyshim

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
)

// guard returns the routeguard.Guard the legacy routes draw on: Shim.Guard,
// or the process-wide default the canonical routes share.
func (s *Shim) guard() *routeguard.Guard { return routeguard.Or(s.Guard) }

// readGuarded takes a ticket for route and reads r's body; when jsonRoute,
// the read takes the ticket's JSON slot once the body is in. On failure it
// has answered the request and returns false; on success the caller owns the
// ticket.
func (s *Shim) readGuarded(w http.ResponseWriter, r *http.Request, route routeguard.Route, jsonRoute bool) (*routeguard.Ticket, []byte, bool) {
	t, err := s.guard().Begin(jsonRoute)
	if err != nil {
		writeLegacyGuardError(w, r, err)
		return nil, nil, false
	}
	body, err := t.ReadBody(w, r, route.WithMaxBody(s.MaxBodyBytes))
	if err != nil {
		t.Close()
		if errors.Is(err, routeguard.ErrBusy) || errors.Is(err, routeguard.ErrReadTimeout) {
			writeLegacyGuardError(w, r, err)
		} else {
			// Neither busy nor slow: an *http.MaxBytesError (body over its
			// cap) or another read error ReadBody passed through as-is —
			// still the guard refusing the body, just not through
			// writeLegacyGuardError's envelope, so it is logged here
			// directly under its own reason.
			refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonBodyRejected)
			writeLegacyError(w, http.StatusBadRequest, "failed to read body")
		}
		return nil, nil, false
	}
	return t, body, true
}

// guardedSubmit is one /overlay/submit the guard has admitted. sub is nil
// when the engine is not an *engine.Engine (the tests' fakes), which then gets
// the BEEF through Submit unverified by the guard.
type guardedSubmit struct {
	t   *routeguard.Ticket
	sub *routeguard.Submit
}

// preVerify normalizes and verifies the BEEF under the guard, as the
// canonical /submit does, before the engine sees it, within
// routeguard.VerifyBudget, the client's connection and deadline. On error
// the ticket is still the caller's.
func (s *Shim) preVerify(r *http.Request, deadline time.Time, t *routeguard.Ticket, beefBytes []byte, topics []string) (*guardedSubmit, error) {
	eng, ok := s.Engine.(*engine.Engine)
	if !ok {
		return &guardedSubmit{t: t}, nil
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	known := eng.ListTopicManagers()
	sub, err := t.PreVerify(ctx, eng.ChainTracker, func(topic string) bool {
		_, ok := known[topic]
		return ok
	}, beefBytes, topics)
	if err != nil {
		return nil, err
	}
	return &guardedSubmit{t: t, sub: sub}, nil
}

// errSubmitPanicked is the outcome of an engine submit that panicked.
var errSubmitPanicked = errors.New("internal error while submitting")

// runSubmit runs the engine's submit on the detached goroutine and returns
// its outcome. A guarded submit hands the engine the normalized BEEF, and its
// lookup services get it as an Atomic BEEF (routeguard.Submit.Atomic) rather
// than beefBytes. A panic anywhere below it, go-sdk's broadcast and lookup
// code included, is logged with its stack and becomes a 500 for this submit,
// not the end of the process. Once the engine returns, everything the submit
// held from the guard is returned.
func (s *Shim) runSubmit(ctx context.Context, g *guardedSubmit, beefBytes []byte, topics []string, onSteakReady engine.OnSteakReady) (out submitOutcome) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("legacyshim: overlay engine panicked during /overlay/submit", "panic", p, "stack", string(debug.Stack()))
			out = submitOutcome{err: errSubmitPanicked}
		}
		if g.sub != nil {
			g.sub.Done()
		} else {
			g.t.Close()
		}
	}()
	var steak overlay.Steak
	var err error
	if g.sub != nil {
		eng := s.Engine.(*engine.Engine)
		steak, err = eng.SubmitParsedBeef(ctx, g.sub.Beef, g.sub.Txid, topics, g.sub.Atomic, nil, engine.SubmitModeCurrent, g.sub.OnSteakReady(onSteakReady))
	} else {
		steak, err = s.Engine.Submit(ctx, overlay.TaggedBEEF{Beef: beefBytes, Topics: topics}, engine.SubmitModeCurrent, onSteakReady)
	}
	return submitOutcome{steak: steak, err: err}
}

// writeLegacyGuardError answers, in the legacy {"error": msg} envelope, a
// request the guard refused or whose BEEF failed before the engine saw it:
// 503 with Retry-After when the node is busy, 408 when the body was too slow,
// 400 with beefscan.Code for a BEEF over a cap, 400 with
// routeguard.MalformedScriptCode for an unlocking script ending in an
// undecodable instruction (routeguard.ErrMalformedScript, cold review round 4
// B1), 400 for a BEEF the guard does not accept (routeguard.ErrMalformed),
// 422 with routeguard.ValidationBudgetCode for scripts over the verification
// budget, and otherwise the status the engine's own error got before the
// guard. The six named guard-imposed cases are rate-limit logged via
// refusallog, as the canonical route's writeGuardError does; a
// context.DeadlineExceeded (preVerify's own deadline, not r's) is carved out
// unlogged, matching writeGuardError, since outlasting a verification
// deadline is an ordinary outcome, not the guard refusing a flood; the true
// default -- any other error reaching here -- is logged under
// ReasonOtherGuardError, since it is still the guard (or preVerify ahead of
// the engine) refusing a submit, just for a reason none of the named Reasons
// cover (cold review round 4's NITs: this branch was unlogged).
func writeLegacyGuardError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, routeguard.ErrBusy):
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
		routeguard.SetRetryAfter(w)
		writeLegacyError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, routeguard.ErrReadTimeout):
		refusallog.Log(r, http.StatusRequestTimeout, refusallog.ReasonSlowBody)
		writeLegacyError(w, http.StatusRequestTimeout, err.Error())
	case errors.Is(err, routeguard.ErrTooComplex):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonTooComplex)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "code": beefscan.Code})
	case errors.Is(err, routeguard.ErrMalformedScript):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonMalformedScript)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "code": routeguard.MalformedScriptCode})
	case errors.Is(err, routeguard.ErrMalformed):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonRefusedBEEF)
		writeLegacyError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, routeguard.ErrValidationBudget):
		refusallog.Log(r, http.StatusUnprocessableEntity, refusallog.ReasonValidationBudget)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error(), "code": routeguard.ValidationBudgetCode})
	case errors.Is(err, context.DeadlineExceeded):
		writeLegacyError(w, statusForSubmitError(err), err.Error())
	default:
		refusallog.Log(r, statusForSubmitError(err), refusallog.ReasonOtherGuardError)
		writeLegacyError(w, statusForSubmitError(err), err.Error())
	}
}
