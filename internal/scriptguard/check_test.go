package scriptguard

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// The eras the tests run under: an unmined spend of an unmined output
// (after Chronicle), of an output mined between Genesis and Chronicle, and
// of one mined before Genesis, as spv.Verify builds them.
var (
	afterChronicle = scriptflag.MainNetActivationHeights.BlockValidationFlags(math.MaxUint32, math.MaxUint32)
	afterGenesis   = scriptflag.MainNetActivationHeights.BlockValidationFlags(700_000, math.MaxUint32)
	beforeGenesis  = scriptflag.MainNetActivationHeights.BlockValidationFlags(600_000, math.MaxUint32)
)

var eras = []struct {
	name  string
	flags scriptflag.Flag
}{{"after Chronicle", afterChronicle}, {"after Genesis", afterGenesis}, {"before Genesis", beforeGenesis}}

// lockSpend returns a spend of an output locked by lock, unlocked by unlock.
func lockSpend(lock, unlock []byte) spend {
	ls, us := script.Script(lock), script.Script(unlock)
	s := spendOf(parentOf(&transaction.TransactionOutput{LockingScript: &ls, Satoshis: 50_000}),
		&transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1000})
	s.tx.Inputs[0].UnlockingScript = &us
	return s
}

func check(s spend, flags scriptflag.Flag) error {
	return Check(context.Background(), s.tx, s.vin, s.prevout, flags)
}

// execute runs the real engine on s under flags.
func execute(s spend, flags scriptflag.Flag) error {
	return interpreter.NewEngine().Execute(interpreter.WithTx(s.tx, s.vin, s.prevout),
		interpreter.WithFlags(flags), interpreter.WithContext(context.Background()))
}

// median times f over runs calls.
func median(runs int, f func()) time.Duration {
	ds := make([]time.Duration, runs)
	for i := range ds {
		start := time.Now()
		f()
		ds[i] = time.Since(start)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[runs/2]
}

func honestSpends(t *testing.T) map[string]spend {
	purchase, cancel := ordLockSpends(t)
	return map[string]spend{
		"P2PKH":                p2pkhSpend(t),
		"PushDrop 3x100 bytes": pushDropSpend(t, 100, 100, 100),
		"PushDrop 1 MiB field": pushDropSpend(t, 1<<20),
		"BSV-21 transfer":      bsv21Spend(t),
		"MNEE cosign":          mneeSpend(t),
		"OrdLock purchase":     purchase,
		"OrdLock cancel":       cancel,
	}
}

// TestCheckPassesHonestScripts: every honest shape passes in every era, and
// passes the real engine after Genesis, so no cost guard trips on them.
func TestCheckPassesHonestScripts(t *testing.T) {
	for name, s := range honestSpends(t) {
		for _, era := range eras {
			if err := check(s, era.flags); err != nil {
				t.Errorf("%s, %s: Check = %v, want nil", name, era.name, err)
			}
			if era.flags.HasFlag(scriptflag.UTXOAfterGenesis) {
				if err := execute(s, era.flags); err != nil {
					t.Errorf("%s, %s: fixture fails the engine: %v", name, era.name, err)
				}
			}
			d := median(21, func() { _ = check(s, era.flags) })
			a := newAnalyzer(context.Background(), s.tx, s.vin, s.prevout, era.flags)
			if era.flags.HasFlag(scriptflag.UTXOAfterGenesis) && (a.progs[0].hasGuarded() || a.progs[1].hasGuarded()) {
				_ = a.run() // the analysis Check runs; the others return before it
			}
			t.Logf("%-20s %-16s Check %8.2f us, %5d analysis steps", name, era.name, float64(d.Nanoseconds())/1000, a.work)
		}
	}
}

// TestCheckDoesNotChangeTheTransaction: Check leaves the input's source
// output unset, which the engine's own run sets.
func TestCheckDoesNotChangeTheTransaction(t *testing.T) {
	purchase, _ := ordLockSpends(t)
	purchase.tx.Inputs[0].SourceTransaction = nil
	before := purchase.tx.Hex()
	if err := check(purchase, afterChronicle); err != nil {
		t.Fatal(err)
	}
	if purchase.tx.Inputs[0].SourceTxOutput() != nil || purchase.tx.Hex() != before {
		t.Fatal("Check changed the transaction")
	}
}

// TestCheckRunsConcurrently: Checks of the same transactions at once agree
// with a lone Check; under -race this shows they share nothing they write.
func TestCheckRunsConcurrently(t *testing.T) {
	purchase, _ := ordLockSpends(t)
	refused := bigMulDiv(1 << 20)
	errs := make([]error, 16)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := purchase
			if i%2 == 1 {
				s = refused
			}
			errs[i] = check(s, afterChronicle)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if (i%2 == 1) != errors.Is(err, ErrTooCostly) {
			t.Errorf("Check %d = %v", i, err)
		}
	}
}

func pushData4(b []byte) []byte {
	out := []byte{script.OpPUSHDATA4, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[1:], uint32(len(b)))
	return append(out, b...)
}

// dataPush is b pushed with OP_DATA_<len(b)>, b at most 75 bytes.
func dataPush(b []byte) []byte { return append([]byte{byte(len(b))}, b...) }

// le is n >= 0 as a minimal script number.
func le(n int) []byte {
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append(b, byte(v))
	}
	if len(b) > 0 && b[len(b)-1]&0x80 != 0 {
		b = append(b, 0)
	}
	return b
}

// multisigShape is the reviewer's repro: unlocking OP_0 OP_1 OP_1 OP_1;
// locking [<big> OP_DROP] OP_3DUP*a <3+3a> OP_1 OP_1 OP_1 OP_3DUP*b <3+3b>
// OP_CHECKMULTISIG, every signature 0x01 (no FORKID), so FindAndDelete runs
// once per signature over the whole scriptCode.
func multisigShape(big, a, b int) spend {
	var lock []byte
	if big > 0 {
		lock = append(pushData4(make([]byte, big)), script.OpDROP)
	}
	for i := 0; i < a; i++ {
		lock = append(lock, script.Op3DUP)
	}
	lock = append(lock, dataPush(le(3+3*a))...)
	lock = append(lock, script.Op1, script.Op1, script.Op1)
	for i := 0; i < b; i++ {
		lock = append(lock, script.Op3DUP)
	}
	lock = append(lock, dataPush(le(3+3*b))...)
	lock = append(lock, script.OpCHECKMULTISIG)
	return lockSpend(lock, []byte{script.Op0, script.Op1, script.Op1, script.Op1})
}

// randNum is an n-byte positive minimally encoded number.
func randNum(n int, seed uint64) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	b[n-1] = 0x41
	return b
}

// bigMulDiv is the reviewer's <X> <V> <W> ROT ROT MUL SWAP DIV DROP TRUE.
func bigMulDiv(n int) spend {
	var lock []byte
	for _, seed := range []uint64{0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb} {
		lock = append(lock, pushData4(randNum(n, seed))...)
	}
	lock = append(lock, script.OpROT, script.OpROT, script.OpMUL, script.OpSWAP, script.OpDIV, script.OpDROP, script.OpTRUE)
	return lockSpend(lock, nil)
}

// bigDiv is the reviewer's <A> DUP DUP CAT SWAP DIV: a 2n-byte number over
// an n-byte one.
func bigDiv(n int) spend {
	a := make([]byte, n)
	for i := range a {
		a[i] = byte(i*7 + 3)
	}
	a[n-1] = 0x41
	lock := append(pushData4(a), script.OpDUP, script.OpDUP, script.OpCAT, script.OpSWAP, script.OpDIV, script.OpDROP, script.OpTRUE)
	return lockSpend(lock, nil)
}

// TestCheckRefusesReviewerShapes: each shape the reviewer measured at 10 s
// or more is refused with ErrTooCostly, naming the opcode, well inside the
// 5 s budget, under both eras after Genesis.
func TestCheckRefusesReviewerShapes(t *testing.T) {
	cases := []struct {
		name string
		s    spend
		op   string
	}{
		{"multisig a=b=24990 big=0", multisigShape(0, 24990, 24990), "OP_CHECKMULTISIG"},
		{"multisig a=b=24990 big=1,000,000", multisigShape(1_000_000, 24990, 24990), "OP_CHECKMULTISIG"},
		{"multisig a=b=24990 big=15,000,000", multisigShape(15_000_000, 24990, 24990), "OP_CHECKMULTISIG"},
		{"BigMulDiv n=5,000,000", bigMulDiv(5_000_000), "OP_MUL"},
		{"BigDiv n=8,000,000", bigDiv(8_000_000), "OP_DIV"},
	}
	for _, c := range cases {
		for _, flags := range []scriptflag.Flag{afterChronicle, afterGenesis} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			start := time.Now()
			err := Check(ctx, c.s.tx, 0, c.s.prevout, flags)
			took := time.Since(start)
			cancel()
			if !errors.Is(err, ErrTooCostly) || !containsWord(err.Error(), c.op) {
				t.Errorf("%s: Check = %v, want ErrTooCostly at %s", c.name, err, c.op)
			}
			if took > time.Second {
				t.Errorf("%s: refusal took %v", c.name, took)
			}
			t.Logf("%-34s refused in %8.2f ms: %v", c.name, float64(took.Microseconds())/1000, err)
		}
	}
}

func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] == w && (i+len(w) == len(s) || s[i+len(w)] == ':') {
			return true
		}
	}
	return false
}
