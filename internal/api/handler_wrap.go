package api

import (
	"io"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

// unreadBodyProbe bounds how long serveAndAbandonUnread waits to find out
// whether a request's body has more left in it, once the handler that
// served it has already returned. Short on purpose: for the overwhelming
// majority of requests the body is already fully drained (the next read
// returns io.EOF with no network wait at all), so this only ever adds
// latency on the rare request a handler left unread, and even then just
// long enough to tell "more is buffered" or "the client is still sending"
// apart from "nothing more was ever coming."
const unreadBodyProbe = 50 * time.Millisecond

// serveAndAbandonUnread calls next, then checks whether r's body still has
// bytes neither it nor next read. A handler that refuses or errors out
// early, without reading a declared or chunked body at all, otherwise
// leaves the connection looking normal to net/http, which then tries to
// read and discard the rest of that body itself before it will reuse the
// connection for a kept-alive client's next request — for a body the
// client never finished sending, or never started, that wait does not
// end. This is the general-purpose version of what routeguard.Refuse
// already does for a request guard routes refuse before ReadBody ever
// runs: end the body the same way, so the connection is told to close
// after the answer instead of lingering on an unread body.
//
// A handler that already read its body to completion — every guarded
// route's ReadBody does — leaves this a no-op: the probe read below
// returns io.EOF immediately, with no wait, and the connection stays
// eligible for reuse exactly as it was before this wrap existed.
func serveAndAbandonUnread(next http.Handler, w http.ResponseWriter, r *http.Request) {
	next.ServeHTTP(w, r)
	if r.ContentLength == 0 || r.Body == nil {
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(unreadBodyProbe))
	var probe [1]byte
	n, err := r.Body.Read(probe[:])
	if n == 0 && err == io.EOF {
		_ = rc.SetReadDeadline(time.Time{}) // fully drained: a reused connection reads normally
		return
	}
	routeguard.Refuse(w, r)
}
