// Package refusallog rate-limits the log lines Anvil's guarded routes write
// when they refuse a request. The guard exists to survive a flood of
// refusals; logging every one of them, unrate-limited, would trade the
// resource exhaustion the guard prevents for a disk/CPU one in the log
// pipeline instead. Log writes at most one line per Reason per interval,
// process-wide, carrying how many refusals of that reason it suppressed
// since the line before — so an operator, or the canary watching this
// node's log for traffic sent straight to its port, still sees that a
// refusal is happening and how often, just not one line per request.
package refusallog

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Reason is a short, fixed label for why a route refused a request. It is
// also the rate-limit key, so the vocabulary is deliberately small and
// closed: every Reason is one of the constants below, never text built from
// the request or from the error that triggered it. That closed vocabulary
// is what keeps Logger's memory bounded in the ordinary case; maxReasons
// bounds it even if a future caller breaks that rule.
type Reason string

const (
	// ReasonBusy is routeguard.ErrBusy: the guard's concurrency budget — the
	// big-body slot or the JSON-route slot count — is spent. The route
	// answers 503 with Retry-After. Wired at v3engine.writeGuardError and
	// legacyshim.writeLegacyGuardError.
	ReasonBusy Reason = "busy"
	// ReasonSlowBody is routeguard.ErrReadTimeout: the body did not arrive
	// within the route's read timeout — bodyread's grace period and minimum
	// rate gave up. 408. Wired at v3engine.writeGuardError and
	// legacyshim.writeLegacyGuardError.
	ReasonSlowBody Reason = "slow_body"
	// ReasonTooComplex is routeguard.ErrTooComplex (beefscan.Code): the BEEF
	// costs more than beefscan's verification-cost cap allows. 400. Wired at
	// v3engine.writeGuardError and legacyshim.writeLegacyGuardError.
	ReasonTooComplex Reason = "too_complex"
	// ReasonRefusedBEEF is routeguard.ErrMalformed (beefnorm.ErrRefused): a
	// BEEF go-sdk parses that the guard does not accept, such as proofs of
	// one block that disagree or an input whose spent output only the
	// extended format supplies. 400. Wired at v3engine.writeGuardError and
	// legacyshim.writeLegacyGuardError.
	ReasonRefusedBEEF Reason = "refused_beef"
	// ReasonValidationBudget is routeguard.ErrValidationBudget
	// (routeguard.ValidationBudgetCode): the transaction's scripts cost more
	// CPU than the per-request validation budget allows. 422. Wired at
	// v3engine.writeGuardError and legacyshim.writeLegacyGuardError.
	ReasonValidationBudget Reason = "validation_budget"
	// ReasonBodyRejected is a guard body-read failure that is neither
	// ReasonBusy nor ReasonSlowBody — an *http.MaxBytesError (the body
	// exceeded the route's declared-or-actual cap) or another read error
	// routeguard.Ticket.ReadBody passes through as-is. 400. Wired at
	// legacyshim.readGuarded's own else branch, which answers this case
	// without going through writeLegacyGuardError.
	ReasonBodyRejected Reason = "body_rejected"

	// ReasonPaymentHeaderTooLarge is the x402 payment gate's 431: an
	// X402-Proof or X-BSV-Payment header over its size limit
	// (internal/api/payment_bounds.go's errPaymentHeaderTooLarge). Wired at
	// payment_bounds.go's paymentRejectionStatus, called from payment.go's
	// two rejection sites. That lane is outside this package's own guard
	// errors; the constant lets its call site and this package's other
	// callers share one vocabulary.
	ReasonPaymentHeaderTooLarge Reason = "payment_header_too_large"
	// ReasonBroadcastTooComplex is POST /broadcast's refusal of a BEEF
	// beefscan finds too costly, with its own 422 (spv.ConfidenceInvalid): a
	// second site over the same cap as ReasonTooComplex but outside
	// routeguard. Kept distinct so the two routes' volumes are told apart.
	// Wired at internal/api/handlers_broadcast.go's handleBroadcast.
	ReasonBroadcastTooComplex Reason = "broadcast_too_complex"
	// ReasonMalformedScript is routeguard.ErrMalformedScript
	// (routeguard.MalformedScriptCode): an unlocking script whose node-exact
	// parse ends in an undecodable instruction, the B1 reparse-heap-bomb
	// trigger. 400. Wired at v3engine.writeGuardError and
	// legacyshim.writeLegacyGuardError.
	ReasonMalformedScript Reason = "malformed_script"
	// ReasonInvalidTransaction is engine.ErrInvalidTransaction or
	// engine.ErrInvalidBeef reaching the default branch of writeGuardError
	// or writeLegacyGuardError: PreVerify's own scripts-did-not-verify
	// fallback, or a BEEF with no subject transaction, neither one the guard
	// refusing for a resource reason. Carved out of ReasonOtherGuardError
	// (cold review round 4 cycle 6 NIT) so a flood of genuinely invalid
	// transactions is told apart, in the log, from the guard's own limits
	// kicking in; the status each route answers is unchanged (legacy keeps
	// mapping these through statusForSubmitError, canonical keeps its flat
	// 400 default) -- only the logged reason changes.
	ReasonInvalidTransaction Reason = "invalid_transaction"
	// ReasonOtherGuardError is any routeguard-surfaced error that reaches the
	// default branch of writeGuardError or writeLegacyGuardError, other than
	// ReasonInvalidTransaction: a submit refused before the engine saw it,
	// for a reason none of the other Reasons name. Logging it closes the gap
	// cold review round 4's NITs flagged -- that branch was previously
	// unlogged -- without widening the closed Reason vocabulary for every
	// future case there.
	ReasonOtherGuardError Reason = "other_guard_error"
	// ReasonPendingCapExceeded is the x402 pending-challenge cap's 503
	// (PaymentGate.reservePending): too many challenges are outstanding.
	// Wired at internal/api/payment.go's issueChallengeForPayees.
	ReasonPendingCapExceeded Reason = "pending_cap_exceeded"
	// ReasonMintBudgetExceeded is the x402 nonce mint budget's 503
	// (*mintBudgetError): the process-wide wallet-mint token bucket is
	// spent. Wired at internal/api/payment.go's issueChallengeForPayees.
	ReasonMintBudgetExceeded Reason = "mint_budget_exceeded"
)

// overflowReason is the shared entry for any Reason beyond maxReasons
// distinct keys (see maxReasons). Logging under it works like any other
// Reason — rate-limited, with its own suppressed count — so a flood of
// unexpected Reasons stays visible instead of silently growing memory.
const overflowReason Reason = "overflow"

// maxReasons bounds Logger.entries independently of Reason's vocabulary
// being fixed today. If a future caller passes a Reason outside the
// constants above — or request-derived text, by mistake — growth stops at
// maxReasons distinct keys; anything past that shares overflowReason instead
// of growing the map further. 32 is generous slack over the handful of
// Reasons this package and its sibling call sites define.
const maxReasons = 32

// DefaultInterval is how often one Reason may write a log line, process
// wide: once a minute. A refusal happens specifically because load is high
// enough that the guard had to say no; logging every one of them at that
// moment would ask the log pipeline to absorb the same flood the guard is
// absorbing, trading a resource-exhaustion attack for a disk-fill one. A
// minute keeps the worst case — every Reason firing continuously — to a
// small, bounded number of lines a minute rather than a line per request,
// while still telling an operator or the canary watching this node's log
// that something refused within a minute of it starting, and the suppressed
// count tells them the volume.
const DefaultInterval = time.Minute

// entry is one Reason's rate-limit state.
type entry struct {
	lastLogged time.Time
	suppressed int
}

// Logger rate-limits refusal logging to at most one line per Reason per
// interval. The zero Logger is not usable; construct one with New. Safe for
// concurrent use.
type Logger struct {
	interval time.Duration
	logger   *slog.Logger

	mu      sync.Mutex
	entries map[Reason]*entry
}

// New returns a Logger that writes at most one line per Reason per interval,
// through logger. A nil logger resolves to slog.Default() at each call to
// Log, so a later slog.SetDefault still takes effect — matching
// netguard.Contain's convention for an injectable, nil-defaults logger.
func New(interval time.Duration, logger *slog.Logger) *Logger {
	return &Logger{
		interval: interval,
		logger:   logger,
		entries:  make(map[Reason]*entry, maxReasons),
	}
}

// current is the process-wide Logger every guarded route shares.
var current atomic.Pointer[Logger]

func init() { current.Store(New(DefaultInterval, nil)) }

// Default returns the process-wide Logger every guarded route shares.
// Production call sites use the package-level Log, which is Default().Log;
// tests construct their own Logger with New so they neither share state with
// other tests nor depend on this process's real wall clock interval.
func Default() *Logger { return current.Load() }

// SetDefault makes l the process-wide Logger and returns the one it
// replaces, so a test can read the lines the routes write, with rate-limit
// state of its own, and put the previous Logger back after.
func SetDefault(l *Logger) *Logger { return current.Swap(l) }

// Log is Default().Log.
func Log(r *http.Request, status int, reason Reason) {
	current.Load().Log(r, status, reason)
}

// Log records one refusal of reason, answered at status, for r. It writes a
// slog.Warn line — route, status, reason, r's RemoteAddr, and (labelled
// separately, only when present) the X-Forwarded-For and X-Real-IP header
// values — unless an earlier refusal of the same reason already wrote a line
// within the last interval, in which case this call only adds to that
// line's eventual suppressed count.
func (l *Logger) Log(r *http.Request, status int, reason Reason) {
	now := time.Now()

	l.mu.Lock()
	e, ok := l.entries[reason]
	if !ok {
		if len(l.entries) >= maxReasons {
			reason = overflowReason
			e, ok = l.entries[reason]
		}
		if !ok {
			e = &entry{}
			l.entries[reason] = e
		}
	}
	suppressed := e.suppressed
	logNow := e.lastLogged.IsZero() || now.Sub(e.lastLogged) >= l.interval
	if logNow {
		e.lastLogged = now
		e.suppressed = 0
	} else {
		e.suppressed++
	}
	l.mu.Unlock()

	if !logNow {
		return
	}

	logger := l.logger
	if logger == nil {
		logger = slog.Default()
	}
	args := []any{
		"status", status,
		"reason", string(reason),
		"route", r.URL.Path,
		"remote_addr", r.RemoteAddr,
		"suppressed", suppressed,
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		args = append(args, "x_forwarded_for", xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		args = append(args, "x_real_ip", xri)
	}
	logger.Warn("refused request", args...)
}
