package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// POST /broadcast takes a verified tip update of a tracked origin as its
// own credential. These bound the attempts: per client, keyed as the API's
// other limiters key it (trust_proxy and trust_proxy_hops respected), at
// most tipCredentialRate a second with a burst of tipCredentialBurst, since
// each attempt that names a tip runs SPV. A request over the limit is
// gated as if the credential did not exist.
const (
	tipCredentialRate  = 1
	tipCredentialBurst = 5
	// maxBroadcastBody is readBEEF's body cap.
	maxBroadcastBody = 10 << 20
	// maxRecordedResponse bounds the copy kept of the broadcast reply, a
	// small JSON object.
	maxRecordedResponse = 64 << 10
)

// TipCredential is what POST /broadcast asks of the node's version tracker
// (internal/ordtrack's Tracker) to take a tip update as its own credential.
type TipCredential interface {
	// Active reports whether any tracked origin has a tip to follow.
	Active() bool
	// SpendsTip returns the tracked origin, and its current tip, that tx
	// spends: one map lookup per input.
	SpendsTip(tx *transaction.Transaction) (origin, tip string, ok bool)
	// VerifyTipUpdate verifies, from what n holds alone, that n's subject
	// moves tip to a new 1-sat output, by the forward rule and spv.Verify.
	// accept records the update; it is called once the broadcast succeeds.
	VerifyTipUpdate(ctx context.Context, n *beefnorm.BEEF, origin, tip string) (accept func(), err error)
}

// trackingSlot holds what SetTipCredential installs.
type trackingSlot struct{ p atomic.Pointer[trackingHooks] }

type trackingHooks struct {
	cred    TipCredential
	limiter *RateLimiter
	stats   func() map[string]int64
	used    atomic.Int64
}

// SetTipCredential makes POST /broadcast accept, without a token or a
// payment, a request whose BEEF verifiably moves a tracked origin's current
// tip to a new 1-sat output. stats, with the count of such broadcasts, is
// merged into GET /stats under "tracking". A nil tc removes both.
func (s *Server) SetTipCredential(tc TipCredential, stats func() map[string]int64) {
	if tc == nil {
		s.tracking.p.Store(nil)
		return
	}
	s.tracking.p.Store(&trackingHooks{
		cred:    tc,
		limiter: NewRateLimiterWithBurst(tipCredentialRate, tipCredentialBurst, s.messageboxLimiter.trustProxy, s.messageboxLimiter.trustHops),
		stats:   stats,
	})
}

// tipCredential runs ahead of gated, POST /broadcast's token-or-payment
// gate. A request is taken as a tip update only after, in order: tracking
// is set up and some tracked origin has a tip; the request carries no
// credential of its own; the client is within its attempt limit; the body
// is within readBEEF's cap and holds a BEEF that beefnorm accepts; one of
// the subject's inputs spends a tracked tip (a map lookup); and the
// tracker verifies the spend. Only that last check runs SPV. A tip update
// is then broadcast by handler as a gated request would be, from the BEEF
// just verified, and recorded once the broadcast of that same transaction
// succeeds. Every other request reaches gated with its body as received,
// so its reply is the one it gets today.
func (s *Server) tipCredential(handler, gated http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := s.tracking.p.Load()
		if h == nil || r.Method != http.MethodPost || carriesCredential(r) || !h.cred.Active() {
			gated(w, r)
			return
		}
		if !h.limiter.Allow(rateLimitKey(clientIP(r, h.limiter.trustProxy, h.limiter.trustHops))) {
			gated(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBroadcastBody+1))
		r.Body = replayBody{Reader: io.MultiReader(bytes.NewReader(body), r.Body), Closer: r.Body}
		if err != nil || len(body) > maxBroadcastBody {
			gated(w, r)
			return
		}
		u, ok := s.verifyTipUpdate(r, h, body)
		if !ok {
			gated(w, r)
			return
		}
		// The handler reads the BEEF verified, not the bytes received, so
		// what it broadcasts is the transaction checked.
		vr := r.Clone(r.Context())
		vr.Body = io.NopCloser(bytes.NewReader(u.beef))
		vr.ContentLength = int64(len(u.beef))
		vr.Header.Set("Content-Type", "application/octet-stream")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		rec := &broadcastRecorder{ResponseWriter: w}
		handler(rec, vr)
		if rec.succeeded(u.txid) {
			u.accept()
			h.used.Add(1)
		}
	}
}

// tipUpdate is a verified tip update: its subject's txid, its BEEF and how
// to record it.
type tipUpdate struct {
	txid   string
	beef   []byte
	accept func()
}

// verifyTipUpdate reports whether body is a verified tip update.
func (s *Server) verifyTipUpdate(r *http.Request, h *trackingHooks, body []byte) (*tipUpdate, bool) {
	beef, err := readBEEF(&http.Request{Header: r.Header, Body: io.NopCloser(bytes.NewReader(body))})
	if err != nil {
		return nil, false
	}
	n, err := parseBEEFSafely(beef)
	if err != nil || n.Tx == nil {
		return nil, false
	}
	origin, tip, spends := h.cred.SpendsTip(n.Tx)
	if !spends {
		return nil, false
	}
	accept, err := h.cred.VerifyTipUpdate(r.Context(), n, origin, tip)
	if err != nil {
		s.logger.Debug("broadcast not taken as a tip update", "origin", origin, "error", err)
		return nil, false
	}
	verified, err := n.Atomic()
	if err != nil {
		return nil, false
	}
	return &tipUpdate{txid: n.Subject.String(), beef: verified, accept: accept}, true
}

// carriesCredential reports whether r carries a token or a payment, which
// the gate alone judges.
func carriesCredential(r *http.Request) bool {
	for _, name := range []string{"X-Anvil-Auth", "Authorization", "X-App-Token", HeaderX402Proof, HeaderBSVPayment} {
		if r.Header.Get(name) != "" {
			return true
		}
	}
	return false
}

// parseBEEFSafely is beefnorm.Parse behind a panic recover.
func parseBEEFSafely(b []byte) (n *beefnorm.BEEF, err error) {
	defer func() {
		if p := recover(); p != nil {
			n, err = nil, fmt.Errorf("BEEF parse panicked: %v", p)
		}
	}()
	return beefnorm.Parse(b)
}

// replayBody gives back the bytes already read, then the rest of the body.
type replayBody struct {
	io.Reader
	io.Closer
}

// broadcastRecorder passes the broadcast reply through and keeps its status
// and the start of its body.
type broadcastRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (b *broadcastRecorder) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *broadcastRecorder) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if room := maxRecordedResponse - b.body.Len(); room > 0 {
		b.body.Write(p[:min(len(p), room)])
	}
	return b.ResponseWriter.Write(p)
}

// succeeded reports a 200 for txid whose status is not rejected.
func (b *broadcastRecorder) succeeded(txid string) bool {
	var resp BroadcastResponse
	if b.status != http.StatusOK || json.Unmarshal(b.body.Bytes(), &resp) != nil || resp.TxID != txid {
		return false
	}
	switch resp.Status {
	case BroadcastStatusPropagated, BroadcastStatusQueued, BroadcastStatusValidatedOnly:
		return true
	}
	return false
}

// trackingStats is what GET /stats shows under "tracking", or nil.
func (s *Server) trackingStats() map[string]int64 {
	h := s.tracking.p.Load()
	if h == nil {
		return nil
	}
	out := map[string]int64{}
	if h.stats != nil {
		for k, v := range h.stats() {
			out[k] = v
		}
	}
	out["broadcast_tip_credential_used"] = h.used.Load()
	return out
}

// SubscribeEnvelopes calls fn, on a goroutine of its own, with each
// envelope on topic that reaches /data/subscribe's stream: those received
// from the mesh through the gossip manager's envelope hook, and those
// accepted on POST /data. Up to 64 wait; more are dropped. stop ends it.
func (s *Server) SubscribeEnvelopes(topic string, fn func(*envelope.Envelope)) (stop func()) {
	ch := make(chan *envelope.Envelope, 64)
	unsubscribe := s.sseHub.subscribe(topic, ch)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case env := <-ch:
				fn(env)
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			unsubscribe()
			close(done)
		})
	}
}
