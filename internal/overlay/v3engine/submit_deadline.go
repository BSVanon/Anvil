package v3engine

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// DefaultSubmitTimeout bounds one POST /submit when Handlers.SubmitTimeout is
// unset. It is the legacy /overlay/submit shim's cap (legacyshim's
// submitBackgroundCap), so both submit routes give up at the same point. It
// exceeds the 30 s each go-sdk propagation lookup is allowed, and fits within
// the 60 s a typical reverse proxy waits, so a caller sees this node's 504.
//
// The cap matters because /submit runs spv.Verify on a client's BEEF with no
// login, and script cost grows with the BEEF: a 1.1 MB BEEF of 20,000
// OP_DUP OP_SHA256 OP_DROP over a 1 MiB push runs for about 8.6 s, and a
// 64 MiB body for hours. go-sdk v1.7.7's interpreter checks the context
// before every opcode, so the deadline stops the CPU as well as the request.
const DefaultSubmitTimeout = 45 * time.Second

func (h *Handlers) submitTimeout() time.Duration {
	if h.SubmitTimeout <= 0 {
		return DefaultSubmitTimeout
	}
	return h.SubmitTimeout
}

// submitContext returns the context POST /submit runs engine.Submit under,
// as the legacy shim builds it: detached from the client connection, so a
// disconnect cannot abort a half-finished commit, and capped, so no submit
// outlives the cap.
func (h *Handlers) submitContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), h.submitTimeout())
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
