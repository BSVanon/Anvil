package hostiletest

import (
	"runtime"
	"sync/atomic"
	"time"
)

// HeapPeak runs f and returns the highest runtime.MemStats.HeapInuse sampled
// while it ran, every two milliseconds, above the HeapInuse just before it,
// measured after a garbage collection.
func HeapPeak(f func()) (peak, base uint64) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	base = m.HeapInuse

	var top atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > top.Load() {
				top.Store(m.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	f()
	close(stop)
	<-done
	if top.Load() <= base {
		return 0, base
	}
	return top.Load() - base, base
}

// Allocated is how many bytes of heap the process has allocated since it
// started. Its rise across a run bounds how far the heap in use rose during
// the run, however briefly, where HeapPeak's sampling can miss a peak that
// lasts under its two milliseconds.
func Allocated() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// HeapKept is how much more heap is in use, after a garbage collection, than
// base, as HeapPeak measured it.
func HeapKept(base uint64) int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse) - int64(base)
}

const (
	// LookupBudget is the memory peerhygiene's budget.go sets aside for the
	// lookup path: LookupSlots answers decoding at once, each within the
	// per-answer caps, and the answers a resolver keeps until its last host
	// replies.
	LookupBudget = 256 << 20
	// HeapMargin allows for the test's own servers and for sampling noise.
	HeapMargin = 32 << 20
	// CostliestHosts is how many hosts answer one query with the costliest
	// reply in the many-hosts tests. A resolver keeps every decoded answer
	// until its last host replies, about 5 MiB of heap in use for each of
	// these replies since peerhygiene.MaxAnswerBEEFBytes is 2 MiB, and the
	// decoding slots do not bound that, so the count must stay under about
	// 50 to fit the budget. At 48 the slots' effect is plain: with them a
	// query peaked at 234 to 262 MiB in testing, without them at 363 to
	// 371 MiB.
	CostliestHosts = 48
)
