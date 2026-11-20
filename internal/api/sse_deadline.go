package api

import (
	"io"
	"net/http"
	"time"
)

// sseWriteDeadline bounds how long a single SSE write+flush may take. A
// client that opens a stream and simply stops reading (no malice required —
// a buggy consumer, a dead NAT mapping, a laptop that went to sleep) leaves
// the OS send buffer with nowhere to drain: once it fills, a plain
// w.Write/Flusher.Flush call blocks in the kernel forever. Every SSE
// handler's stream-cap slot (acquireChaintracksStream, acquireMessageStream)
// and its goroutine are released only by a deferred call on return, so an
// unbounded block there pins both forever. A var, not a const, so a test can
// shrink it — same pattern as sseHeartbeatInterval and the per-client/global
// SSE cap vars already in this package.
var sseWriteDeadline = 10 * time.Second

// writeSSE sets a fresh per-write deadline on w — best-effort: a
// ResponseWriter that does not support deadlines (e.g. a test double with no
// real socket behind it) just gets an unbounded write, which is harmless,
// since nothing about an in-memory fake can block the way a real stalled
// socket does — then writes data (data may be "" for a header-only flush)
// and flushes. Any write or flush error, including a deadline exceeded while
// blocked on a dead client, is returned so the caller's SSE loop can return
// immediately: its deferred release() then frees the stream's per-client/
// global cap slot instead of holding it on a connection that will never
// drain.
func writeSSE(w http.ResponseWriter, data string) error {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(sseWriteDeadline))
	if data != "" {
		if _, err := io.WriteString(w, data); err != nil {
			return err
		}
	}
	return rc.Flush()
}
