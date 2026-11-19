package v3engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// opReturn is an OP_FALSE OP_RETURN output script carrying n bytes.
func opReturn(n int) *script.Script {
	s := &script.Script{}
	_ = s.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	_ = s.AppendPushData(bytes.Repeat([]byte{0xAB}, n))
	return s
}

// chainBEEF is a BEEF of an unproven chain of n transactions, each with an
// OP_RETURN output of data bytes.
func chainBEEF(t *testing.T, n, data int) []byte {
	lock := script.Script{script.OpTRUE}
	prev := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &lock, Satoshis: 100_000})
	for i := 1; i < n; i++ {
		tx := transaction.NewTransaction()
		tx.AddInputFromTx(prev, 0, nil)
		tx.Inputs[0].UnlockingScript = &script.Script{}
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 100_000 - uint64(i)})
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: opReturn(data)})
		prev = tx
	}
	b, err := prev.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spendWith spends a parent output locked by lock with unlock, into outputs.
func spendWith(t *testing.T, lock, unlock *script.Script, outs ...*transaction.TransactionOutput) []byte {
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 50_000})
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = unlock
	for _, o := range outs {
		child.AddOutput(o)
	}
	b, err := child.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bigUHRP is an admissible UHRP advertisement whose URL is urlLen bytes long.
func bigUHRP(t *testing.T, urlLen int) []byte {
	s := &script.Script{}
	_ = s.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	_ = s.AppendPushData([]byte(topics.UHRPProtocolID))
	_ = s.AppendPushData(bytes.Repeat([]byte{0x11}, 32))
	_ = s.AppendPushData([]byte("https://x.test/" + strings.Repeat("a", urlLen)))
	_ = s.AppendPushData([]byte("image/png"))
	b, err := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: s, Satoshis: 0}).BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// arcPathBody is an /arc-ingest body whose merkle path holds n leaves on one
// level, the first of them the txid.
func arcPathBody(n int) []byte {
	var b bytes.Buffer
	b.Write([]byte{0xfd, 0x10, 0x27}) // block height 10000
	b.WriteByte(1)                    // tree height
	b.Write([]byte{0xfd, byte(n), byte(n >> 8)})
	txid := bytes.Repeat([]byte{0x01}, 32)
	for i := 0; i < n; i++ {
		b.Write([]byte{0xfd, byte(i), byte(i >> 8)})
		if i == 0 {
			b.WriteByte(2)
			b.Write(txid)
			continue
		}
		b.WriteByte(0)
		b.Write(bytes.Repeat([]byte{byte(i)}, 32))
	}
	var id [32]byte
	for i := range id {
		id[i] = txid[31-i]
	}
	return []byte(`{"txid":"` + hex.EncodeToString(id[:]) + `","merklePath":"` + hex.EncodeToString(b.Bytes()) + `","blockHeight":10000}`)
}

// livePeak sends one request through a fresh engine behind a fresh guard and
// returns its status and the heap it held at its peak, with garbage
// collected at 2%, so the peak is close to what the request held live rather
// than what the collector had yet to free. The engine is the request's own,
// so no earlier request's storage work lands in the peak, and the
// measurement lasts until the handler returns its reservation: a submit
// answers at onSteakReady and commits after.
func livePeak(t *testing.T, send func(url string) int) (code int, peak uint64) {
	return heapPeak(t, 2, send)
}

// heapPeak is livePeak with garbage collected at gcPercent instead.
func heapPeak(t *testing.T, gcPercent int, send func(url string) int) (code int, peak uint64) {
	t.Helper()
	eng, _ := newTestEngine(t)
	g := freshGuard(routeguard.CPUSlots)
	url := guardedServer(t, eng, g)
	defer debug.SetGCPercent(debug.SetGCPercent(gcPercent))
	peak, _ = hostiletest.HeapPeak(func() {
		code = send(url)
		idle, err := g.Begin(false)
		if err == nil {
			err = idle.Reserve(context.Background(), routeguard.MemoryBudget-routeguard.ExecAllowance)
			idle.Close()
		}
		if err != nil {
			t.Errorf("the handler did not return its reservation: %v", err)
		}
	})
	return code, peak
}

// TestGuard_WeightsCoverTheMeasuredPeaks: the heap each route reserves for a
// body covers what the costliest measured shapes hold live through the
// route, and a script that writes a 32 MiB stack element stays within the
// execution slot's allowance. For the large BEEF bodies and that script the
// reservation also covers the heap in use at the default GOGC, uncollected
// garbage included; for the other shapes it does not (see MemoryBudget).
func TestGuard_WeightsCoverTheMeasuredPeaks(t *testing.T) {
	big := int(routeguard.MaxBEEFBody) - 4096
	ops := routeguard.MaxScriptOps
	trueOut := &transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1}
	pushOut, _ := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: opReturn(big)}).BEEF()
	nops := script.Script(append(bytes.Repeat([]byte{script.OpNOP}, ops-1), script.OpTRUE))
	dups := script.Script(append([]byte{0x01, 0x01}, bytes.Repeat([]byte{script.OpDUP}, ops-1)...))
	cat := &script.Script{}
	_ = cat.AppendPushData(bytes.Repeat([]byte{0x42}, 1024))
	for i := 0; i < 15; i++ {
		_ = cat.AppendOpcodes(script.OpDUP, script.OpCAT)
	}
	_ = cat.AppendOpcodes(script.OpDROP, script.OpTRUE)
	for _, c := range []struct {
		name      string
		body      []byte
		budget    int64 // 0: the route's reservation for the body
		defaultGC bool  // the budget covers the peak at the default GOGC too
	}{
		{"16 MiB push in an output", pushOut, 0, true},
		{"admitted UHRP with a 16 MiB URL", bigUHRP(t, big-300), 0, false},
		{"unproven chain of 1,200", chainBEEF(t, 1200, 6_900), 0, true},
		{"50,000 OP_NOPs verified", spendWith(t, &nops, &script.Script{}, trueOut), 0, false},
		{"a stack 50,000 OP_DUPs deep", spendWith(t, &dups, &script.Script{}, trueOut), 0, false},
		{"a 32 MiB element built with OP_CAT", spendWith(t, cat, &script.Script{}, trueOut), routeguard.ExecAllowance, true},
	} {
		budget := c.budget
		if budget == 0 {
			budget, _ = routeguard.BEEFRoute.Reservation(int64(len(c.body)))
		}
		gcs := []int{2}
		if c.defaultGC {
			gcs = append(gcs, 100)
		}
		for _, gc := range gcs {
			code, peak := heapPeak(t, gc, func(url string) int {
				code, _, _, _ := submitTo(context.Background(), url, c.body)
				return code
			})
			t.Logf("%-34s %9d bytes: %d, GOGC=%-3d peak %6.1f MiB of %6.1f MiB", c.name, len(c.body), code, gc, float64(peak)/(1<<20), float64(budget)/(1<<20))
			if code != http.StatusOK || peak > uint64(budget) {
				t.Errorf("%s at GOGC=%d: answered %d holding %d bytes, over the %d it may", c.name, gc, code, peak, budget)
			}
		}
	}
	fill := func(prefix, unit, suffix string) []byte {
		n := (int(routeguard.MaxJSONBody) - 64 - len(prefix) - len(suffix)) / len(unit)
		return []byte(prefix + strings.TrimSuffix(strings.Repeat(unit, n), ",") + suffix)
	}
	// The SLAP service decodes the whole query into interface{} values before
	// it reads the fields it knows. The test's chain tracker knows no block,
	// so the merkle path is decoded, parsed and checked, then refused.
	for _, c := range []struct {
		name, path string
		route      routeguard.Route
		body       []byte
		want       int
	}{
		{"SLAP lookup of 1 MiB of objects", "/lookup", routeguard.LookupRoute, fill(`{"service":"ls_slap","query":{"pad":[`, `{},`, `]}}`), http.StatusOK},
		{"merkle path of 14,000 leaves", "/arc-ingest", routeguard.ArcIngestRoute, arcPathBody(14_000), http.StatusBadRequest},
	} {
		code, peak := livePeak(t, func(url string) int {
			resp, err := (&http.Client{}).Post(url+c.path, "application/json", bytes.NewReader(c.body))
			if err != nil {
				t.Error(err)
				return 0
			}
			resp.Body.Close()
			return resp.StatusCode
		})
		budget, _ := c.route.Reservation(int64(len(c.body)))
		t.Logf("%-34s %9d bytes: %d, GOGC=2   peak %6.1f MiB of %6.1f MiB", c.name, len(c.body), code, float64(peak)/(1<<20), float64(budget)/(1<<20))
		if code != c.want || peak > uint64(budget) {
			t.Errorf("%s: answered %d, want %d, holding %d bytes of the %d it reserved", c.name, code, c.want, peak, budget)
		}
	}
}
