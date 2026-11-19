package v3engine

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// DefaultSubmitTimeout bounds the engine's part of one POST /submit when
// Handlers.SubmitTimeout is unset: verification, admission, commit and the
// start of propagation. It is the legacy /overlay/submit shim's cap
// (legacyshim's submitBackgroundCap), so both submit routes give up at the
// same point. It is not the whole request: a submit that reaches propagation
// answers 200 once propagation's POSTs to other hosts end, each within
// netguard.SubmitTimeout (15 s), so a submit can take up to 30 + 15 = 45 s
// (measured 44.5 s, legacyshim's TestSubmitChain_WorstCase, which drives both
// submit routes through the same worst case), under nginx's default 60 s
// proxy_read_timeout (deploy/nginx-anvil.conf) — the prior 45 + 15 = 60 s cap
// left no margin below that default and could be cut by it mid-commit
// (review finding S8).
//
// 30 s equals, rather than exceeds, each go-sdk propagation lookup's own
// allowance (lookup.MAX_TRACKER_WAIT_TIME, topic.MAX_SHIP_QUERY_TIMEOUT, both
// 30 s): a submit whose admission is itself slow leaves the SHIP/SLAP lookup
// less than its full 30 s of this deadline, which can then end the submit
// early with 504 instead of waiting out go-sdk's own cap. That is the
// intended trade — a prompt, bounded failure instead of a request that can
// outlast the proxy — not a hang.
//
// The cap matters because /submit runs spv.Verify on a client's BEEF with no
// login, and script cost grows with the BEEF. The guard's own verification
// stops a submit's scripts at routeguard.VerifyBudget (5 s) before the engine
// sees them; go-sdk v1.7.7's interpreter checks the context before every
// opcode, so the deadline stops the CPU as well as the request.
const DefaultSubmitTimeout = 30 * time.Second

func (h *Handlers) submitTimeout() time.Duration {
	if h.SubmitTimeout <= 0 {
		return DefaultSubmitTimeout
	}
	return h.SubmitTimeout
}

// submitContext returns the context POST /submit runs the engine under, as
// the legacy shim builds it: detached from the client connection, so a
// disconnect cannot abort a half-finished commit, and ending at deadline, the
// submit's cap. The cap stops verification, Anvil topic admission and the
// start of propagation; a commit already under way runs to completion, and
// the route then answers 200 (v3engine's detached storage and lookup views).
// Propagation's own POSTs to other hosts ignore the context and are bounded
// by netguard.SubmitTimeout instead, so a submit can outlast the cap by up to
// 15 s (see DefaultSubmitTimeout).
func (h *Handlers) submitContext(r *http.Request, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.WithoutCancel(r.Context()), deadline)
}

// submitErrorStatus maps an engine.Submit error to the canonical route's
// status: 504 when the cap cut the submit short, as the legacy shim's
// statusForSubmitError does, and 400 for everything else, as before.
func submitErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadRequest
}
