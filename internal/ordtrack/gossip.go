package ordtrack

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TipTopic is the mesh topic peers publish verified tips on.
const TipTopic = "ordtip:v1"

const (
	// tipTTL is a tip envelope's lifetime in seconds. Tip envelopes are
	// never durable: a late peer follows the chain itself.
	tipTTL = 3600
	// defaultGossipPayload is the envelope payload cap a tip envelope keeps
	// under: the node's envelope payload cap, [envelopes] max_durable_size,
	// whose default is 65536 bytes. The tip's BEEF rides along only when
	// the payload still fits with it.
	defaultGossipPayload = 65536

	// Peers' hints are taken at most one per signer every hintSignerEvery,
	// with a burst of hintSignerBurst, and at most hintGlobalRate per second
	// across every signer, with a burst of hintGlobalBurst: a hint without
	// a BEEF costs the fetch of the transaction it names. At most
	// maxHintSigners signers are tracked at once.
	hintSignerEvery = 10 * time.Second
	hintSignerBurst = 5
	hintGlobalRate  = 1
	hintGlobalBurst = 10
	maxHintSigners  = 1000
)

// tipHint is a tip envelope's payload.
type tipHint struct {
	Origin  string `json:"origin"`
	PrevTip string `json:"prevTip"`
	NewTip  string `json:"newTip"`
	BEEF    string `json:"beef,omitempty"` // hex
}

// publish signs and sends a tip envelope for a tip this node verified.
func (t *Tracker) publish(origin, prevTip, newTip string, beef []byte) {
	if t.cfg.Publish == nil || t.cfg.SigningKey == nil {
		return
	}
	h := tipHint{Origin: origin, PrevTip: prevTip, NewTip: newTip}
	payload, err := json.Marshal(h)
	if err != nil {
		return
	}
	if len(beef) > 0 {
		h.BEEF = hex.EncodeToString(beef)
		if withBEEF, err := json.Marshal(h); err == nil && len(withBEEF) <= t.cfg.MaxGossipPayload {
			payload = withBEEF
		}
	}
	if len(payload) > t.cfg.MaxGossipPayload {
		return
	}
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     TipTopic,
		Payload:   string(payload),
		TTL:       tipTTL,
		Timestamp: t.now().Unix(),
	}
	env.Sign(t.cfg.SigningKey)
	t.cfg.Publish(env)
}

// HandleEnvelope takes a peer's tip envelope. A hint for an origin this
// node does not track, or for a spend of anything but the tip it holds,
// is ignored. Any other hint is rate limited and handed to the spend watch
// as a candidate, its BEEF kept for the verification: the signer is never
// trusted, and nothing changes until the spend verifies here.
func (t *Tracker) HandleEnvelope(env *envelope.Envelope) {
	if env == nil || env.Topic != TipTopic {
		return
	}
	var h tipHint
	if len(env.Payload) > t.cfg.MaxGossipPayload || json.Unmarshal([]byte(env.Payload), &h) != nil {
		t.gossipRejected.Add(1)
		return
	}
	origin, ok1 := NormalizeOutpoint(h.Origin)
	prev, ok2 := NormalizeOutpoint(h.PrevTip)
	next, ok3 := NormalizeOutpoint(h.NewTip)
	if !ok1 || !ok2 || !ok3 {
		t.gossipRejected.Add(1)
		return
	}
	t.mu.Lock()
	ch := t.chains[origin]
	current := ch != nil && ch.isOpen() && ch.tip.Outpoint == prev
	t.mu.Unlock()
	if !current {
		return
	}
	if env.Validate() != nil || !t.hints.allow(strings.ToLower(env.Pubkey), t.now()) {
		t.gossipRejected.Add(1)
		return
	}
	txid, _, _ := splitOutpoint(next)
	if h.BEEF != "" {
		raw, err := hex.DecodeString(h.BEEF)
		n, perr := parseBEEF(raw)
		if err != nil || perr != nil || n.Subject.String() != txid {
			t.gossipRejected.Add(1)
			return
		}
		t.mu.Lock()
		t.beefs.put(txid, n, raw, t.now())
		t.mu.Unlock()
	}
	t.mu.Lock()
	t.hinted[txid] = struct{}{}
	if len(t.hinted) > queueSize {
		for k := range t.hinted {
			delete(t.hinted, k)
			break
		}
	}
	t.mu.Unlock()
	t.watch.Hint(prev, txid)
}

// hintLimiter is a token bucket per signer plus one across all signers.
type hintLimiter struct {
	mu      sync.Mutex
	signers map[string]*tokens
	global  tokens
}

type tokens struct {
	n    float64
	last time.Time
}

func newHintLimiter() *hintLimiter {
	return &hintLimiter{signers: make(map[string]*tokens), global: tokens{n: hintGlobalBurst}}
}

func (b *tokens) take(now time.Time, perSec, burst float64) bool {
	if !b.last.IsZero() {
		b.n += now.Sub(b.last).Seconds() * perSec
	}
	b.last = now
	if b.n > burst {
		b.n = burst
	}
	if b.n < 1 {
		return false
	}
	b.n--
	return true
}

func (h *hintLimiter) allow(signer string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.signers[signer]
	if s == nil {
		if len(h.signers) >= maxHintSigners {
			for k, v := range h.signers {
				if now.Sub(v.last) > time.Minute {
					delete(h.signers, k)
				}
			}
			if len(h.signers) >= maxHintSigners {
				return false
			}
		}
		s = &tokens{n: hintSignerBurst}
		h.signers[signer] = s
	}
	perSigner := 1 / hintSignerEvery.Seconds()
	if !s.take(now, perSigner, hintSignerBurst) {
		return false
	}
	return h.global.take(now, hintGlobalRate, hintGlobalBurst)
}
