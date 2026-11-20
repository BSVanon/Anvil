package api

import (
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// Replay protection for direct payments. An X-Bsv-Payment is not bound to a
// challenge, so without it one transaction would pay for any number of
// requests. BRC-121 section 5 step 5 refuses a replayed payment with 402
// (0121.md:97). The gate remembers the txid of every direct payment it accepts
// and refuses that txid again with ERR_PAYMENT_REPLAYED.
//
// The memory is bounded: a txid is kept for directPaymentReplayWindow, and at
// most directPaymentReplayCapacity txids are kept, the oldest evicted first.
// Measured full (TestDirectPaymentReplaySetMemory): 9.2 MB (8.8 MiB) of heap.
// The set lives in memory only, so a restart empties it. A payment that ARC
// reports as mined deeper than maxDirectPaymentDepth blocks is refused
// whether or not the set remembers it (checkPaymentDepth, payment_arc.go), so
// neither eviction nor a restart reopens an old mined payment. The known
// limit: after a restart, a payment accepted in the last 24 hours that is
// still unmined, or mined at most maxDirectPaymentDepth blocks deep, pays once
// more.
const (
	directPaymentReplayWindow   = 24 * time.Hour
	directPaymentReplayCapacity = 100_000
)

// replayEntry is one accepted payment txid and when it was accepted, as the
// time since the set was made (monotonic, and 8 bytes rather than 24).
type replayEntry struct {
	txid chainhash.Hash
	at   time.Duration
}

// paymentReplaySet holds the txids of accepted direct payments, and the txids
// being verified right now, so that two requests carrying the same payment at
// once cannot both pass.
type paymentReplaySet struct {
	mu       sync.Mutex
	now      func() time.Time
	base     time.Time // when the set was made
	window   time.Duration
	capacity int
	accepted map[chainhash.Hash]struct{}
	inFlight map[chainhash.Hash]struct{}
	ring     []replayEntry // accepted txids in acceptance order, oldest at head
	head     int
	size     int
}

func newPaymentReplaySet(window time.Duration, capacity int, now func() time.Time) *paymentReplaySet {
	return &paymentReplaySet{
		now:      now,
		base:     now(),
		window:   window,
		capacity: capacity,
		accepted: make(map[chainhash.Hash]struct{}),
		inFlight: make(map[chainhash.Hash]struct{}),
	}
}

// begin claims txid for one verification. It returns false when txid was
// accepted within the window, or when another request is verifying it now.
// Every true return must be followed by end.
func (s *paymentReplaySet) begin(txid chainhash.Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	if _, ok := s.accepted[txid]; ok {
		return false
	}
	if _, ok := s.inFlight[txid]; ok {
		return false
	}
	s.inFlight[txid] = struct{}{}
	return true
}

// end releases begin's claim. An accepted payment's txid is remembered; a
// refused one's is forgotten, so the payer can retry it, for example after ARC
// was unreachable.
func (s *paymentReplaySet) end(txid chainhash.Hash, accepted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, txid)
	if !accepted {
		return
	}
	s.expire()
	if s.size >= s.capacity {
		s.popOldest()
	}
	s.push(replayEntry{txid: txid, at: s.now().Sub(s.base)})
	s.accepted[txid] = struct{}{}
}

// expire forgets the txids accepted longer than the window ago.
func (s *paymentReplaySet) expire() {
	cutoff := s.now().Sub(s.base) - s.window
	for s.size > 0 && s.ring[s.head].at <= cutoff {
		s.popOldest()
	}
}

func (s *paymentReplaySet) popOldest() {
	delete(s.accepted, s.ring[s.head].txid)
	s.ring[s.head] = replayEntry{}
	s.head = (s.head + 1) % len(s.ring)
	s.size--
}

// push appends e at the tail, growing the ring up to capacity entries. The
// caller makes room first, so a ring at capacity is never full here.
func (s *paymentReplaySet) push(e replayEntry) {
	if s.size == len(s.ring) {
		n := min(max(2*len(s.ring), 64), s.capacity)
		grown := make([]replayEntry, n)
		for i := 0; i < s.size; i++ {
			grown[i] = s.ring[(s.head+i)%len(s.ring)]
		}
		s.ring, s.head = grown, 0
	}
	s.ring[(s.head+s.size)%len(s.ring)] = e
	s.size++
}
