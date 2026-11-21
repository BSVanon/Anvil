package routeguard

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/clientkey"
	"golang.org/x/sync/semaphore"
)

// The most one client may hold at once of each budget (see the package
// documentation). A client is the key clientkey gives the address the API's
// rate limits count a request under.
const (
	// ClientReadPermits caps the read permits one client may hold: its
	// requests waiting for, or reading, their bodies. It is the most requests
	// the overlay engine's GASP sync has in flight to one peer at once
	// (engine.NewOverlayGASPRemote's network limit of 8), so a node syncing
	// with this one never meets it, and it takes ReadPermits /
	// ClientReadPermits = 32 clients to hold every read permit.
	ClientReadPermits = 8

	// ClientJSONSlots caps the JSON slots one client may hold, a quarter of
	// JSONSlots: twice what a syncing peer uses.
	ClientJSONSlots = 16

	// ClientCPUSlots caps the CPU slots one client may hold, on a guard of
	// three slots or more. On a smaller guard a client may hold one fewer than
	// the guard has, and at least one, so that one client can never hold them
	// all unless the guard has a single slot.
	ClientCPUSlots = 2

	// ClientMemoryShare divides the pool: one client may hold reserved at once
	// a third of it, or a single reservation larger than that. A third holds
	// the reservation of a 1 MiB BEEF (86.7 MiB of the 284 MiB pool) or of
	// eleven lookups, and it takes three clients to reserve the whole pool
	// with requests of that size.
	ClientMemoryShare = 3
)

// client is what one client holds across its requests' tickets: a semaphore
// for each slot, indexed like Ticket.held, and one for its share of the pool.
type client struct {
	key  string
	refs int // under clientSet.mu: tickets bound to it, and exec hand-offs pending
	slot [5]*semaphore.Weighted
	mem  *semaphore.Weighted
	cap  int64 // mem's size
}

// proxyTrust is the API's trust_proxy setting, which tells the guard where to
// find a request's client.
type proxyTrust struct {
	trust bool
	hops  int
}

// clientSet finds the client of each request and keeps the clients that hold
// anything.
type clientSet struct {
	mu    sync.Mutex
	byKey map[string]*client
	slots [5]int64 // the caps, indexed like Ticket.held
	mem   int64
	proxy atomic.Pointer[proxyTrust]

	warnings *hourlyWarn
	warn     func(msg string, args ...any)
}

// newClientSet sets the caps for a guard of the given pool and slot counts.
func newClientSet(pool, cpuSlots, jsonSlots int64) *clientSet {
	s := &clientSet{byKey: map[string]*client{}, mem: max(1, pool/ClientMemoryShare), warn: slog.Warn, warnings: newHourlyWarn()}
	s.slots[slotRead] = min(ClientReadPermits, ReadPermits)
	s.slots[slotJSON] = min(ClientJSONSlots, max(1, jsonSlots-1))
	s.slots[slotCPU] = min(ClientCPUSlots, max(1, cpuSlots-1))
	s.slots[slotBig] = 1
	s.slots[slotExec] = 1
	return s
}

// hourlyWarn tracks, per condition key, when it last let a warning through:
// at most once an hour each, rather than a sync.Once's forever (cold review
// round 4 RISK 8, "a later misconfiguration is never logged"). now is
// time.Now, overridden in tests.
type hourlyWarn struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

func newHourlyWarn() *hourlyWarn {
	return &hourlyWarn{last: map[string]time.Time{}, now: time.Now}
}

// allow reports whether key may warn now: the first time it is asked, or
// once an hour has passed since the last time it was let through.
func (h *hourlyWarn) allow(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if last, ok := h.last[key]; ok && now.Sub(last) < time.Hour {
		return false
	}
	h.last[key] = now
	return true
}

// TrustProxy sets how the guard finds the client of a request, as the API's
// rate limits do with api.trust_proxy and api.trust_proxy_hops (see
// clientkey.IP). Until it is called a guard trusts a proxy only on the
// loopback interface, for the rightmost X-Forwarded-For entry, the shipped
// nginx configuration's.
func (g *Guard) TrustProxy(trust bool, hops int) {
	g.clients.proxy.Store(&proxyTrust{trust: trust, hops: hops})
}

// keyOf is the key of r's client, or false when r's chosen address is the
// TCP peer address itself (not one trust_proxy took from X-Forwarded-For)
// and that address may stand for many clients (clientkey.Shared), whose
// requests only the node's own limits count. A key trust_proxy took from
// X-Forwarded-For never falls back this way, forged private or loopback or
// not: it is the client's own word, and lifting the cap on it would let any
// direct client escape by claiming one (cold review round 4 RISK 9). Either
// case it meets first for the guard's life is logged once.
func (s *clientSet) keyOf(r *http.Request) (string, bool) {
	trust, hops := false, 1
	if p := s.proxy.Load(); p != nil {
		trust, hops = p.trust, p.hops
	}
	ip := clientkey.IP(r, trust, hops)
	if ip == clientkey.Peer(r) && clientkey.Shared(ip) {
		if s.warnings.allow("shared") {
			s.warn("overlay routes: per-client limits do not apply to requests from this address, a loopback, private or shared one that may stand for many clients; only the node's own limits count them. "+
				"Expected for local tools. If a proxy sends the node its traffic, have it name each client in X-Forwarded-For, with api.trust_proxy and api.trust_proxy_hops set unless it runs on this host. Logged at most once an hour.",
				"address", ip, "forwarded", clientkey.Forwarded(r))
		}
		return "", false
	}
	if clientkey.Forwarded(r) && ip == clientkey.Peer(r) && s.warnings.allow("ignored") {
		if clientkey.HasXFF(r) {
			s.warn("overlay routes: requests from this address name other clients in X-Forwarded-For, which the node does not use, so the per-client limits count all of them as one client. "+
				"If it is a proxy of yours, set api.trust_proxy and api.trust_proxy_hops; if not, nothing needs doing. Logged at most once an hour.",
				"address", ip, "trust_proxy", trust)
		} else {
			s.warn("overlay routes: requests from this address name a client in X-Real-IP or Forwarded, which trust_proxy cannot use: it reads only X-Forwarded-For. "+
				"If it is a proxy of yours, have it send X-Forwarded-For instead (or as well), with api.trust_proxy and api.trust_proxy_hops set; if not, nothing needs doing. Logged at most once an hour.",
				"address", ip, "trust_proxy", trust)
		}
	}
	return clientkey.Key(ip), true
}

// ref returns r's client with a reference taken, or nil when r's address may
// stand for many clients.
func (s *clientSet) ref(r *http.Request) *client {
	key, ok := s.keyOf(r)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.byKey[key]
	if c == nil {
		c = &client{key: key, mem: semaphore.NewWeighted(s.mem), cap: s.mem}
		for i, n := range s.slots {
			c.slot[i] = semaphore.NewWeighted(n)
		}
		s.byKey[key] = c
	}
	c.refs++
	return c
}

// hold takes one more reference on c.
func (s *clientSet) hold(c *client) {
	s.mu.Lock()
	c.refs++
	s.mu.Unlock()
}

// unref returns a reference on c, and forgets c once nothing refers to it:
// by then it holds nothing.
func (s *clientSet) unref(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.refs--; c.refs == 0 && s.byKey[c.key] == c {
		delete(s.byKey, c.key)
	}
}

// size is how many clients hold anything.
func (s *clientSet) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byKey)
}

// takeClientRead finds r's client (keyOf) and, when r declares a body, takes
// that client's read-permit share: ErrBusy, with r's body refused unread
// (refuse), when the client holds ClientReadPermits already. own reports
// whether a share was taken, false for an empty body or an address that may
// stand for many clients, which is still returned (with a reference taken)
// so Begin can bind the ticket to it. The caller takes the guard's own read
// permit next, the same order as every other slot (slots.go), and must give
// this back (giveBackRead) if that fails.
func (s *clientSet) takeClientRead(w http.ResponseWriter, r *http.Request) (cl *client, own bool, err error) {
	cl = s.ref(r)
	if cl == nil || r.ContentLength == 0 {
		return cl, false, nil
	}
	if !cl.slot[slotRead].TryAcquire(1) {
		s.unref(cl)
		Refuse(w, r)
		return nil, false, ErrBusy
	}
	return cl, true, nil
}

// giveBackRead undoes takeClientRead when the guard's own read permit was
// not free to complete the pair: own's share, if any, and cl's reference.
func (s *clientSet) giveBackRead(cl *client, own bool) {
	if cl == nil {
		return
	}
	if own {
		cl.slot[slotRead].Release(1)
	}
	s.unref(cl)
}

// ownSlot is the client's semaphore for slot i, nil when the ticket is bound
// to no client. Under t.mu.
func (t *Ticket) ownSlot(i int) *semaphore.Weighted {
	if t.cl == nil {
		return nil
	}
	return t.cl.slot[i]
}

// settle returns to the client what the ticket's reservation no longer
// covers: the ticket holds of its client's share min(t.mem, the share).
// Under t.mu.
func (t *Ticket) settle() {
	if t.cl == nil {
		return
	}
	if over := t.clMem - min(t.mem, t.cl.cap); over > 0 {
		t.clMem -= over
		t.cl.mem.Release(over)
	}
}

// unbind returns the ticket's reference on its client, once it holds nothing
// of the client's. Under t.mu.
func (t *Ticket) unbind() {
	if t.cl != nil {
		t.g.clients.unref(t.cl)
		t.cl = nil
	}
}
