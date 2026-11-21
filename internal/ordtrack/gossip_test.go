package ordtrack

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func newKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	k, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// hint is a tip envelope signed by key.
func hint(key *ec.PrivateKey, origin, prev, next string, beef []byte) *envelope.Envelope {
	p := tipHint{Origin: origin, PrevTip: prev, NewTip: next}
	if beef != nil {
		p.BEEF = hex.EncodeToString(beef)
	}
	payload, _ := json.Marshal(p)
	env := &envelope.Envelope{Type: "data", Topic: TipTopic, Payload: string(payload), TTL: tipTTL, Timestamp: time.Now().Unix()}
	env.Sign(key)
	return env
}

// peer is a second node over the same chain and store.
func (h *harness) peer() *harness {
	p := &harness{
		t: h.t, ctx: h.ctx, w: h.w, chain: h.chain, store: h.store, src: &source{store: h.store},
		woc: h.woc, clock: h.clock, key: newKey(h.t), dir: h.t.TempDir(),
	}
	p.open()
	return p
}

func TestAValidHintIsApplied(t *testing.T) {
	a := newHarness(t)
	o := a.mint("v0")
	origin := op(o, 0)
	a.track(origin)
	b := a.peer()
	b.track(origin)

	// Node a takes a broadcast and publishes the new tip with its BEEF.
	v1 := a.move(o, 0, a.inscribed("v1"))
	a.tr.NoteBroadcast(v1, ordtracktest.AtomicBEEF(t, v1))
	a.observe(v1)
	envs := a.envelopes()
	if len(envs) != 1 || envs[0].Validate() != nil || envs[0].Topic != TipTopic || envs[0].TTL != tipTTL || envs[0].Durable {
		t.Fatalf("published %+v", envs)
	}
	var p tipHint
	if err := json.Unmarshal([]byte(envs[0].Payload), &p); err != nil || p.Origin != origin || p.PrevTip != origin || p.NewTip != op(v1, 0) || p.BEEF == "" {
		t.Fatalf("payload %+v, %v", p, err)
	}

	// Node b verifies it from the BEEF alone and applies it.
	before := b.store.Calls.Load()
	b.tr.HandleEnvelope(envs[0])
	b.drain()
	b.wantLatest(origin, op(v1, 0), true)
	if b.stat("ordtip_gossip_applied") != 1 || b.stat("ordtip_gossip_rejected") != 0 {
		t.Fatalf("stats = %v", b.tr.Stats())
	}
	if n := b.store.Calls.Load() - before; n != 0 {
		t.Fatalf("%d fetches for a hint carrying its BEEF", n)
	}
	if len(b.envelopes()) != 0 {
		t.Fatal("a tip learned from a peer was published again")
	}

	// A hint without a BEEF is verified from what the node fetches.
	v2 := a.move(v1, 0, a.inscribed("v2"))
	b.tr.HandleEnvelope(hint(newKey(t), origin, op(v1, 0), op(v2, 0), nil))
	b.drain()
	b.wantLatest(origin, op(v2, 0), true)
	if b.stat("ordtip_gossip_applied") != 2 {
		t.Fatalf("stats = %v", b.tr.Stats())
	}
}

func TestATipEnvelopeLeavesOutABEEFThatDoesNotFit(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	h.tr.cfg.MaxGossipPayload = 400
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.tr.NoteBroadcast(v1, ordtracktest.AtomicBEEF(t, v1))
	h.observe(v1)
	envs := h.envelopes()
	if len(envs) != 1 || len(envs[0].Payload) > 400 || strings.Contains(envs[0].Payload, "beef") {
		t.Fatalf("published %+v", envs)
	}
}

func TestForgedHintsAreRejected(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	stolen := h.moveBy(ordtracktest.NewWallet(t), o, 0, h.inscribed("stolen"))
	key := newKey(t)

	tampered := hint(key, origin, origin, op(v1, 0), nil)
	tampered.Payload = strings.Replace(tampered.Payload, v1.TxID().String(), stolen.TxID().String(), 1)
	other := hint(key, origin, origin, op(v1, 0), ordtracktest.AtomicBEEF(t, stolen))
	notHex := hint(key, origin, origin, op(v1, 0), nil)
	notHex.Payload = strings.Replace(notHex.Payload, `"}`, `","beef":"zz"}`, 1)
	notHex.Sign(key)
	badOutpoint := hint(key, origin, origin, "not-an-outpoint", nil)
	notJSON := &envelope.Envelope{Type: "data", Topic: TipTopic, Payload: "{", TTL: tipTTL}
	notJSON.Sign(key)
	for name, env := range map[string]*envelope.Envelope{
		"tampered after signing": tampered, "BEEF of another tx": other, "BEEF not hex": notHex,
		"bad outpoint": badOutpoint, "not JSON": notJSON,
	} {
		before := h.stat("ordtip_gossip_rejected")
		h.tr.HandleEnvelope(env)
		if h.stat("ordtip_gossip_rejected") != before+1 || len(h.tr.queue) != 0 {
			t.Fatalf("%s: rejected %d -> %d, queued %d", name, before, h.stat("ordtip_gossip_rejected"), len(h.tr.queue))
		}
	}

	// A well-formed hint for a spend that does not verify: rejected when
	// verified, nothing changed.
	h.tr.HandleEnvelope(hint(key, origin, origin, op(stolen, 0), ordtracktest.AtomicBEEF(t, stolen)))
	h.drain()
	h.wantTip(origin, origin)
	if h.stat("ordtip_gossip_rejected") != 6 || h.stat("ordtip_gossip_applied") != 0 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
}

func TestHintsForUntrackedOriginsOrOldTipsAreIgnored(t *testing.T) {
	h := newHarness(t)
	o, untracked := h.mint("v0"), h.mint("u")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)
	u1 := h.move(untracked, 0, h.inscribed("u1"))
	key := newKey(t)
	before := h.store.Calls.Load()
	for _, env := range []*envelope.Envelope{
		hint(key, op(untracked, 0), op(untracked, 0), op(u1, 0), ordtracktest.AtomicBEEF(t, u1)),
		hint(key, origin, origin, op(v1, 0), nil), // not the current tip
		{Type: "data", Topic: "other:v1", Payload: "{}", TTL: 60},
	} {
		h.tr.HandleEnvelope(env)
	}
	if len(h.tr.queue) != 0 || h.stat("ordtip_gossip_rejected") != 0 || h.store.Calls.Load() != before {
		t.Fatalf("queued %d, stats %v, fetches %d", len(h.tr.queue), h.tr.Stats(), h.store.Calls.Load()-before)
	}
}

func TestHintsAreRateLimitedPerSigner(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	noisy, quiet := newKey(t), newKey(t)
	next := func(i int) string { return outpointString(fmt.Sprintf("%064x", i+1), 0) }
	for i := 0; i < hintSignerBurst+1; i++ {
		h.tr.HandleEnvelope(hint(noisy, origin, origin, next(i), nil))
	}
	if got := len(h.tr.queue); got != hintSignerBurst || h.stat("ordtip_gossip_rejected") != 1 {
		t.Fatalf("queued %d, stats %v; want %d queued, 1 rejected", got, h.tr.Stats(), hintSignerBurst)
	}
	h.tr.HandleEnvelope(hint(quiet, origin, origin, next(9), nil))
	if got := len(h.tr.queue); got != hintSignerBurst+1 {
		t.Fatalf("another signer's hint: queued %d", got)
	}
	// The global bucket caps every signer together.
	for i := 0; i < hintGlobalBurst; i++ {
		h.tr.HandleEnvelope(hint(newKey(t), origin, origin, next(i%9), nil))
	}
	if got := len(h.tr.queue); got != hintGlobalBurst {
		t.Fatalf("queued %d past the global burst of %d", got, hintGlobalBurst)
	}
}
