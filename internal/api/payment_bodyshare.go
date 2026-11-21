package api

import (
	"errors"
	"net/http"
	"sync"
)

// One client may hold only a share of the payment body-read permits
// (paymentBodyReads, payment_bodyread.go), so that bodies one client stalls
// cannot take every permit from the others.

// paymentBodyClientShare is how many payment-route bodies one client may have
// in their reads at once, those still waiting for a permit included. A client
// is keyed as the node's rate limiter keys it (PaymentGate.clientKeyFor).
const paymentBodyClientShare = 4

// errPaymentBodyShare means the client already has its share of bodies in
// their reads. It is answered 503 with codePaymentBodyShare and a Retry-After
// (writePaymentBodyError, payment_bodyread.go).
var errPaymentBodyShare = errors.New("this client already has its share of payment request bodies being read")

// paymentBodyShares counts each client's bodies in their reads. A var so
// tests can use a smaller share.
var paymentBodyShares = newBodyShares(paymentBodyClientShare)

// bodyShares counts the reads each client key holds, at most limit each. A
// key is dropped once its count is back to zero, so the map holds only the
// clients with a read in progress.
type bodyShares struct {
	mu    sync.Mutex
	held  map[string]int
	limit int
}

func newBodyShares(limit int) *bodyShares {
	return &bodyShares{held: make(map[string]int), limit: limit}
}

// take counts one more read for key, unless key already holds limit of them.
// leave gives it back the first time it is called and does nothing after.
func (s *bodyShares) take(key string) (leave func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[key] >= s.limit {
		return nil, false
	}
	s.held[key]++
	var once sync.Once
	return func() { once.Do(func() { s.give(key) }) }, true
}

func (s *bodyShares) give(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held[key]--
	if s.held[key] <= 0 {
		delete(s.held, key)
	}
}

// holding is how many reads key holds, and clients how many keys hold any.
func (s *bodyShares) holding(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[key]
}

func (s *bodyShares) clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

// clientKeyFor is the key r's client is counted under: the node's rate-limit
// key (rateLimitKey, auth.go) for the client address that the server's
// trust_proxy settings choose (newServerPaymentGate), or, for a gate built
// without them, the address chosen with trust_proxy off, as the rate limiter
// chooses it by default.
func (pg *PaymentGate) clientKeyFor(r *http.Request) string {
	if pg.clientKey != nil {
		return pg.clientKey(r)
	}
	return rateLimitKey(clientIP(r, false, 1))
}
