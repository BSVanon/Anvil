package legacyshim

import (
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

// answerWriteGrace is the fixed share of an answer's write deadline that
// applies regardless of size: a round trip plus proxy and TLS overhead on
// an answer that would otherwise be instant.
const answerWriteGrace = 5 * time.Second

// boundAnswerWrite sets a deadline on w's connection sized to n bytes at
// routeguard.MinBodyRate, the same floor rate a request body of that size
// is held to. A client on a genuinely slow link still receives its answer,
// but a client that never reads it at all no longer holds whatever ticket
// served it open for as long as it keeps the connection — only until this
// deadline. A writer with no underlying connection, as in a test double,
// silently keeps no deadline at all; SetWriteDeadline then reports that it
// is unsupported, which this ignores the same way routeguard's own pacer
// does for the read side.
func boundAnswerWrite(w http.ResponseWriter, n int) {
	d := answerWriteGrace
	if n > 0 {
		d += time.Duration(n/int(routeguard.MinBodyRate)+1) * time.Second
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
}

// writeJSONBytes writes an already-serialized JSON body with the given
// status: the same headers as writeJSON, for a caller that serializes
// first so it knows the answer's size before any of it reaches the wire.
func writeJSONBytes(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}
