package topics

import (
	"fmt"
	"log/slog"
)

// admitLogger carries an optional structured logger used to surface
// topic-admission skip reasons. It closes an observability gap between
// Anvil's Go topic managers and their canonical TypeScript sources: the
// canonical managers narrate admission, Anvil's ports did not.
//
// For example KVStoreTopicManager.identifyAdmissibleOutputs (ts-stack
// 29aff6e) logs, for every output that decoded as a KVStore token but
// failed validation:
//
//	console.debug(`[KVStoreTopicManager] Skipping output ${i}: ${error}`)
//
// and, when a submit admits nothing and consumes no previous coins:
//
//	console.warn('No KVStore outputs admitted, and no previous KVStore coins were consumed.')
//
// Anvil's ports skipped both silently, so a submitting dev (or an
// operator) could not tell why a token bounced — only that /submit
// returned 200 with an empty STEAK.
//
// This type adds ONLY observability. The HTTP contract is unchanged: an
// unadmitted-but-well-formed submit still returns 200 with empty
// admittance, exactly as the canonical overlay-services Engine.submit
// does (it catches per-topic errors into empty AdmittanceInstructions
// and returns the STEAK regardless). Nothing here can turn a 200 into a
// 4xx.
//
// A zero-value admitLogger (nil logger) discards every call, so existing
// zero-arg NewXxxTopicManager() constructions keep compiling and stay
// silent; production wiring injects a logger via WithLogger.
type admitLogger struct{ l *slog.Logger }

// skip logs one output that decoded as a topic-shaped token but failed
// validation, mirroring the canonical per-output console.debug. reason
// is the specific cause (bad signature, malformed field, unsupported
// version, …). Logged at Debug: it is expected admission filtering, not
// an error, and matches the canonical debug level. Non-topic outputs are
// never passed here — they are skipped silently, as the canonical
// managers do for shape mismatches.
func (a admitLogger) skip(topic string, output int, reason any) {
	if a.l == nil {
		return
	}
	a.l.Debug("overlay: skipped output during topic admission",
		"topic", topic, "output", output, "reason", fmt.Sprint(reason))
}

// nothingAdmitted logs a submit that admitted no outputs and consumed no
// previous coins for this topic, mirroring the canonical console.warn.
// Logged at Warn so it is visible at the default log level: a submit
// that changes nothing is the exact condition the reporting dev hit.
func (a admitLogger) nothingAdmitted(topic string) {
	if a.l == nil {
		return
	}
	a.l.Warn("overlay: no outputs admitted and no previous coins consumed",
		"topic", topic)
}

// TopicOption configures a canonical topic manager at construction.
type TopicOption func(*admitLogger)

// WithLogger attaches a structured logger for admission-skip diagnostics.
// A nil logger is valid and disables the diagnostics (the pre-existing
// silent behavior).
func WithLogger(l *slog.Logger) TopicOption {
	return func(a *admitLogger) { a.l = l }
}

// newAdmitLogger folds the supplied options into an admitLogger.
func newAdmitLogger(opts ...TopicOption) admitLogger {
	var a admitLogger
	for _, o := range opts {
		if o != nil {
			o(&a)
		}
	}
	return a
}
