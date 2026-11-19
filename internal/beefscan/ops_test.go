package beefscan

import (
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// sdkOps names the go-sdk calls that untrusted BEEF bytes reach in Anvil
// before beefnorm normalizes them, in the order timeOps runs them: the parse,
// of an Atomic BEEF's inner bytes. What runs after (beefnorm's extraction of
// the BUMPs its entries name, both verifications, AtomicBytes, the lookup
// services' NewTransactionFromBEEF and the engine's Clone and Bytes) runs on
// the normalized BEEF, and beefnorm's tests time it.
var sdkOps = [...]string{"NewBeefFromBytes"}

// opTimes holds one duration per entry of sdkOps.
type opTimes [len(sdkOps)]time.Duration

// timeOps times each of sdkOps on b.
func timeOps(b []byte) (d opTimes) {
	inner := b
	if len(b) >= 36 && binary.LittleEndian.Uint32(b) == transaction.ATOMIC_BEEF {
		inner = b[36:]
	}
	d[0] = elapsed(func() { _, _ = transaction.NewBeefFromBytes(inner) })
	return d
}

// slowest is the longest of d and the call that took it.
func (d opTimes) slowest() (string, time.Duration) {
	i := 0
	for j := range d {
		if d[j] > d[i] {
			i = j
		}
	}
	return sdkOps[i], d[i]
}

// fastestOf runs timeOps up to tries times and keeps each call's fastest
// time, stopping early once every call is inside limit. Other packages' tests
// share this machine, so one slow run alone proves nothing; a cost the caps
// fail to bound is slow every time.
func fastestOf(b []byte, tries int, limit time.Duration) opTimes {
	best := timeOps(b)
	for i := 1; i < tries; i++ {
		if _, worst := best.slowest(); worst <= limit {
			break
		}
		next := timeOps(b)
		for j := range best {
			best[j] = min(best[j], next[j])
		}
	}
	return best
}

func elapsed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// liveHeap is peerhygiene's answer_cost_test liveHeap, copied: it runs f with
// garbage collection at 2% and returns the most heap allocated while it ran,
// sampled from exact snapshots every 50 microseconds, and what its result
// keeps after a collection, each above the heap before it ran. Garbage not
// yet collected counts towards the peak, so it can only read high.
func liveHeap(f func() any) (peak, kept uint64) {
	defer debug.SetGCPercent(debug.SetGCPercent(2))
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	base := m.HeapAlloc
	var top atomic.Uint64
	note := func(v uint64) {
		for old := top.Load(); v > old && !top.CompareAndSwap(old, v); old = top.Load() {
		}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			note(m.HeapAlloc)
			time.Sleep(50 * time.Microsecond)
		}
	}()
	result := f()
	close(stop)
	<-done
	runtime.ReadMemStats(&m)
	note(m.HeapAlloc)
	runtime.GC()
	runtime.ReadMemStats(&m)
	if m.HeapAlloc > base {
		kept = m.HeapAlloc - base
	}
	runtime.KeepAlive(result)
	if t := top.Load(); t > base {
		peak = t - base
	}
	return peak, kept
}

// parseHeap is ParseBeef's peak heap on b, in bytes: what v3.4.0 measured
// the routes' parse with, and what routeguard's parse allowance cites. It
// holds all that NewBeefFromBytes, which the routes now run, holds.
func parseHeap(b []byte) uint64 {
	peak, _ := liveHeap(func() any {
		beef, tx, _, _ := transaction.ParseBeef(b)
		return []any{beef, tx}
	})
	return peak
}
