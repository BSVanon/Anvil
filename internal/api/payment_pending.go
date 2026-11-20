package api

import (
	"net/http"
	"time"
)

// Bounds on the challenges a PaymentGate keeps pending. A challenge stays in
// pendingChallenges until a proof uses it up or its TTL passes, and it keeps
// the request's method, Host, path and query and the payees' locking scripts,
// which the caller and a topic's publisher choose.

// maxPendingChallenges caps pendingChallenges at 1,024, ten times the default
// nonce pool. Every challenge takes a nonce, so the pool and the mint budget
// (payment_budget.go) already bound how many challenges one TTL can issue; the
// cap holds as well for a larger pool, and for nonces that cost nothing
// (DevNonceProvider).
const maxPendingChallenges = 1024

// maxChallengeFootprint caps the bytes one challenge keeps from the request
// and its payees, 16 KiB, so a full pendingChallenges holds about 17 MiB with
// each challenge's fixed fields. An honest challenge keeps a few hundred bytes;
// a P2PKH payee script is 50 hex characters. Without the cap one challenge
// could keep a request line and Host up to net/http's 1 MiB header limit, and
// a payee script as long as an envelope.
const maxChallengeFootprint = 16 << 10

// challengeFootprint is the number of bytes a challenge for r keeps from the
// request and payees.
func challengeFootprint(r *http.Request, payees []Payee) int {
	n := len(r.Method) + len(r.Host) + len(r.URL.Path) + len(r.URL.RawQuery)
	for _, p := range payees {
		n += len(p.Role) + len(p.LockingScriptHex)
	}
	return n
}

// pendingPlace is a place in pendingChallenges held for a challenge being
// issued. fill hands the place to the challenge and release gives it back,
// each under pg.mu, so a challenge never counts twice against the cap.
type pendingPlace struct {
	pg   *PaymentGate
	done bool // filled or given back; guarded by pg.mu
}

// reservePending holds a place in pendingChallenges for a challenge about to
// be issued, so that a full map refuses the challenge before it takes a
// nonce. A full map first drops its expired challenges. It returns the place,
// or false and how long until a place is likely to free up.
func (pg *PaymentGate) reservePending() (place *pendingPlace, retryAfter time.Duration, ok bool) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if len(pg.pendingChallenges)+pg.reservedPending >= pg.maxPending {
		now := time.Now().Unix()
		earliest := pg.dropExpiredLocked(now)
		if len(pg.pendingChallenges)+pg.reservedPending >= pg.maxPending {
			// A challenge expires once the clock passes its ExpiresAt second.
			// With none pending, the places are held by challenges being
			// issued, which take a second or so.
			wait := time.Second
			if earliest > 0 {
				wait = time.Duration(earliest+1-now) * time.Second
			}
			return nil, wait, false
		}
	}
	pg.reservedPending++
	return &pendingPlace{pg: pg}, 0, true
}

// fill stores p under hash in the place.
func (pl *pendingPlace) fill(hash string, p *pendingChallenge) {
	pl.pg.mu.Lock()
	defer pl.pg.mu.Unlock()
	pl.endReservationLocked()
	pl.pg.pendingChallenges[hash] = p
}

// release gives the place back, unless fill used it.
func (pl *pendingPlace) release() {
	pl.pg.mu.Lock()
	defer pl.pg.mu.Unlock()
	pl.endReservationLocked()
}

func (pl *pendingPlace) endReservationLocked() {
	if !pl.done {
		pl.done = true
		pl.pg.reservedPending--
	}
}

// cleanExpired removes challenges older than their expiry.
func (pg *PaymentGate) cleanExpired() {
	now := time.Now().Unix()
	pg.mu.Lock()
	defer pg.mu.Unlock()
	pg.dropExpiredLocked(now)
}

// dropExpiredLocked removes the challenges that expired before now, a Unix
// time, and returns the earliest ExpiresAt left, or 0 if none is left. pg.mu
// must be held.
func (pg *PaymentGate) dropExpiredLocked(now int64) (earliest int64) {
	for hash, pending := range pg.pendingChallenges {
		if now > pending.challenge.ExpiresAt {
			delete(pg.pendingChallenges, hash)
			continue
		}
		if earliest == 0 || pending.challenge.ExpiresAt < earliest {
			earliest = pending.challenge.ExpiresAt
		}
	}
	return earliest
}
