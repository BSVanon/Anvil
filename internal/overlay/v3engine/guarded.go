package v3engine

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// guard returns the routeguard.Guard the handlers draw on: Handlers.Guard, or
// the process-wide default.
func (h *Handlers) guard() *routeguard.Guard { return routeguard.Or(h.Guard) }

// readJSON takes a ticket for a JSON route and reads r's body for route, which
// takes the ticket's JSON slot once the body is in. On failure it has
// answered the request and returns false; on success the caller closes the
// ticket once it has answered.
func (h *Handlers) readJSON(w http.ResponseWriter, r *http.Request, route routeguard.Route) (*routeguard.Ticket, []byte, bool) {
	t, err := h.guard().Begin(w, r, true)
	if err != nil {
		routeguard.Refuse(w, r)
		writeGuardError(w, r, err, "")
		return nil, nil, false
	}
	body, err := t.ReadBody(w, r, route.WithMaxBody(h.MaxBodyBytes))
	if err != nil {
		t.Close()
		writeGuardError(w, r, err, "read body: ")
		return nil, nil, false
	}
	return t, body, true
}

// submitBEEF serves the body of POST /submit once its headers have passed:
// it reads the body, normalizes and verifies the BEEF under the guard, within
// routeguard.VerifyBudget and the client's connection, and hands the
// normalized BEEF to the engine, which verifies it once more, admits and
// commits it; its lookup services get the normalized BEEF as an Atomic BEEF,
// not the bytes received. SubmitTimeout, counted from the end of the body,
// covers the guard's verification and the engine's work alike.
func (h *Handlers) submitBEEF(w http.ResponseWriter, r *http.Request, topics []string) {
	t, err := h.guard().Begin(w, r, false)
	if err != nil {
		routeguard.Refuse(w, r)
		writeGuardError(w, r, err, "")
		return
	}
	defer t.Close()
	body, err := t.ReadBody(w, r, routeguard.BEEFRoute.WithMaxBody(h.MaxBodyBytes))
	if err != nil {
		writeGuardError(w, r, err, "read body: ")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty body (BEEF required)")
		return
	}
	beefBytes, offChain, err := splitOffChainValues(body, r.Header.Get("x-includes-off-chain-values"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid off-chain values prefix: "+err.Error())
		return
	}
	deadline := time.Now().Add(h.submitTimeout())
	vctx, vcancel := context.WithDeadline(r.Context(), deadline)
	known := h.Engine.ListTopicManagers()
	sub, err := t.PreVerify(vctx, h.Engine.ChainTracker, func(topic string) bool {
		_, ok := known[topic]
		return ok
	}, beefBytes, topics)
	vcancel()
	if err != nil {
		if r.Context().Err() == nil {
			writeGuardError(w, r, err, "submit failed: ")
		}
		return
	}
	ctx, cancel := h.submitContext(r, deadline)
	defer cancel()
	steak, err := h.Engine.SubmitParsedBeef(ctx, sub.Beef, sub.Txid, topics, sub.Atomic, offChain, engine.SubmitModeCurrent, sub.OnSteakReady(nil))
	sub.Done()
	if err != nil {
		writeError(w, submitErrorStatus(err), "submit failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, canonicalSteak(steak))
}

// writeGuardError answers a request the guard refused, or whose submit failed
// before the engine saw it: 503 with Retry-After when the node is busy, 408
// when the body was too slow, 400 with beefscan.Code for a BEEF over a cap,
// 400 for a BEEF the guard does not accept (routeguard.ErrMalformed), 400 with
// routeguard.MalformedScriptCode for an unlocking script ending in an
// undecodable instruction (routeguard.ErrMalformedScript, cold review round 4
// B1), 422 with routeguard.ValidationBudgetCode for scripts over the
// verification budget, and otherwise the status the route answered before the
// guard, with prefix before the message -- the default case's status is
// unchanged by the classification below, always 400 here. The six
// guard-imposed cases (busy, slow body, too complex, refused, malformed
// script, validation budget) are rate-limit logged via refusallog so an
// operator or the canary watching this node can see refusals sent straight to
// its port without every one of a flood becoming its own log line; so is the
// default case, under ReasonInvalidTransaction for engine.ErrInvalidTransaction
// or engine.ErrInvalidBeef (PreVerify's own fallback for scripts that simply
// did not verify, or a BEEF with no subject) and ReasonOtherGuardError for
// anything else reaching here, since both are still the guard refusing a
// submit before the engine saw it, just for reasons the other named Reasons
// do not cover (cold review round 4's NITs: this branch was unlogged; cold
// review round 4 cycle 6's NITs: it was logged but not split from a flood of
// genuinely invalid transactions). The deadline-exceeded case is an ordinary
// request outcome, not the guard protecting the node, so it is not logged
// here.
func writeGuardError(w http.ResponseWriter, r *http.Request, err error, prefix string) {
	switch {
	case errors.Is(err, routeguard.ErrTooComplex):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonTooComplex)
		writeJSON(w, http.StatusBadRequest, errorEnvelope{Status: "error", Code: beefscan.Code, Message: prefix + err.Error()})
	case errors.Is(err, routeguard.ErrMalformedScript):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonMalformedScript)
		writeJSON(w, http.StatusBadRequest, errorEnvelope{Status: "error", Code: routeguard.MalformedScriptCode, Message: prefix + err.Error()})
	case errors.Is(err, routeguard.ErrMalformed):
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonRefusedBEEF)
		writeError(w, http.StatusBadRequest, prefix+err.Error())
	case errors.Is(err, routeguard.ErrValidationBudget):
		refusallog.Log(r, http.StatusUnprocessableEntity, refusallog.ReasonValidationBudget)
		writeJSON(w, http.StatusUnprocessableEntity, errorEnvelope{Status: "error", Code: routeguard.ValidationBudgetCode, Message: prefix + err.Error()})
	case errors.Is(err, routeguard.ErrBusy):
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
		routeguard.SetRetryAfter(w)
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, routeguard.ErrReadTimeout):
		refusallog.Log(r, http.StatusRequestTimeout, refusallog.ReasonSlowBody)
		writeError(w, http.StatusRequestTimeout, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, submitErrorStatus(err), prefix+err.Error())
	default:
		refusallog.Log(r, http.StatusBadRequest, invalidTransactionReason(err))
		writeError(w, http.StatusBadRequest, prefix+err.Error())
	}
}

// invalidTransactionReason is ReasonInvalidTransaction for
// engine.ErrInvalidTransaction or engine.ErrInvalidBeef, and
// ReasonOtherGuardError for every other error writeGuardError's default
// branch logs (cold review round 4 cycle 6 NIT). It changes no status code:
// callers still answer 400 either way.
func invalidTransactionReason(err error) refusallog.Reason {
	if errors.Is(err, engine.ErrInvalidTransaction) || errors.Is(err, engine.ErrInvalidBeef) {
		return refusallog.ReasonInvalidTransaction
	}
	return refusallog.ReasonOtherGuardError
}
