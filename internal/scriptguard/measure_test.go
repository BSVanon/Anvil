package scriptguard

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// The measurements behind the caps' comments. They allocate up to a few
// hundred MiB and take minutes, so they run only with SCRIPTGUARD_MEASURE=1:
//
//	SCRIPTGUARD_MEASURE=1 go test -run TestMeasure -v ./internal/scriptguard/

func measuring(t *testing.T) {
	if os.Getenv("SCRIPTGUARD_MEASURE") == "" {
		t.Skip("set SCRIPTGUARD_MEASURE=1 to measure")
	}
}

// maxElem is about the longest element the default stack memory limit
// (100,000,000 bytes, 32 more an element) admits.
const maxElem = 99_999_000

// timeEngine reports the median of 3 engine runs of lock after unlock.
func timeEngine(t *testing.T, name string, lock, unlock []byte) {
	t.Helper()
	s := lockSpend(lock, unlock)
	var err error
	d := median(3, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = interpreter.NewEngine().Execute(interpreter.WithTx(s.tx, 0, s.prevout),
			interpreter.WithFlags(afterChronicle), interpreter.WithContext(ctx))
	})
	msg := "passes"
	if err != nil {
		msg = err.Error()
		msg = msg[:min(len(msg), 70)]
	}
	t.Logf("%-44s %9.2f ms  (%s)", name, float64(d.Microseconds())/1000, msg)
}

func fill(n int, seed uint64) []byte { return randNum(n, seed) }

// TestMeasureOpcodeFamilies times each opcode family on the largest operands
// that reach it, a script being one push and the opcode.
func TestMeasureOpcodeFamilies(t *testing.T) {
	measuring(t)
	drop := ops(script.OpDROP, script.Op1)
	k := maxArithOperand
	for _, n := range []int{k, 2 * k, 1 << 20} {
		a, b := pushData4(fill(n, 1)), pushData4(fill(n, 2))
		timeEngine(t, "MUL n x n, n="+itoa(n), cat(a, b, ops(script.OpMUL), drop), nil)
		timeEngine(t, "DIV 2n / n, n="+itoa(n), cat(pushData4(fill(2*n, 3)), b, ops(script.OpDIV), drop), nil)
		timeEngine(t, "MOD 2n % n, n="+itoa(n), cat(pushData4(fill(2*n, 3)), b, ops(script.OpMOD), drop), nil)
		timeEngine(t, "DIV n / n/2, n="+itoa(n), cat(a, pushData4(fill(n/2, 4)), ops(script.OpDIV), drop), nil)
	}
	big := pushData4(fill(maxElem, 5))
	for _, op := range []byte{script.OpRIPEMD160, script.OpSHA1, script.OpSHA256, script.OpHASH160, script.OpHASH256} {
		timeEngine(t, "hash 0x"+hex2(op)+" of 99 MB", cat(big, ops(op), drop), nil)
	}
	timeEngine(t, "RIPEMD160 of 32 MiB (cap)", cat(pushData4(fill(maxRipemdInput, 6)), ops(script.OpRIPEMD160), drop), nil)
	timeEngine(t, "NUM2BIN 99 MB -> 99 MB", cat(pushData4(fill(maxElem-64, 7)), dataPush(le(maxElem-64)), ops(script.OpNUM2BIN), drop), nil)
	timeEngine(t, "NUM2BIN 32 MiB (cap) -> 32 MiB", cat(pushData4(fill(maxNum2binInput, 8)), dataPush(le(maxNum2binInput)), ops(script.OpNUM2BIN), drop), nil)
	timeEngine(t, "NUM2BIN 32 MiB (cap) -> 67 MB", cat(pushData4(fill(maxNum2binInput, 9)), dataPush(le(67_000_000)), ops(script.OpNUM2BIN), drop), nil)
	timeEngine(t, "NUM2BIN 1 byte -> 99 MB", cat(ops(script.Op1), dataPush(le(maxElem-64)), ops(script.OpNUM2BIN), drop), nil)
	half1, half2 := pushData4(fill(maxElem/2, 10)), pushData4(fill(maxElem/2, 11))
	zeros, num1, num2 := pushData4(make([]byte, maxElem)), pushData4(fill(32_000_000, 12)), pushData4(fill(32_000_000, 13))
	padded := make([]byte, 32_000_000) // 1 then zeros: BIN2NUM strips them all
	padded[0] = 1
	// Each script is built only when timed, so that one at a time is held.
	for name, build := range map[string]func() []byte{
		"INVERT 99 MB":                  func() []byte { return cat(big, ops(script.OpINVERT), drop) },
		"LSHIFT 99 MB by 1":             func() []byte { return cat(big, ops(script.Op1, script.OpLSHIFT), drop) },
		"RSHIFT 99 MB by 1":             func() []byte { return cat(big, ops(script.Op1, script.OpRSHIFT), drop) },
		"SPLIT 99 MB at 1":              func() []byte { return cat(big, ops(script.Op1, script.OpSPLIT), drop) },
		"BIN2NUM 99 MB":                 func() []byte { return cat(big, ops(script.OpBIN2NUM), drop) },
		"IF on 99 MB":                   func() []byte { return cat(big, ops(script.OpIF, script.OpENDIF, script.Op1)) },
		"VERIF on 99 MB":                func() []byte { return cat(big, ops(script.OpVERIF, script.OpENDIF, script.Op1)) },
		"SUBSTR 99 MB 1 1":              func() []byte { return cat(big, ops(script.Op1, script.Op1, script.OpSUBSTR), drop) },
		"LEFT 99 MB 1":                  func() []byte { return cat(big, ops(script.Op1, script.OpLEFT), drop) },
		"RIGHT 99 MB 1":                 func() []byte { return cat(big, ops(script.Op1, script.OpRIGHT), drop) },
		"IF on 99 MB of zeros":          func() []byte { return cat(zeros, ops(script.OpIF, script.OpENDIF, script.Op1)) },
		"VERIFY on 99 MB of zeros":      func() []byte { return cat(zeros, ops(script.OpVERIFY, script.Op1)) },
		"AND 2x49 MB":                   func() []byte { return cat(half1, half2, ops(script.OpAND), drop) },
		"OR 2x49 MB":                    func() []byte { return cat(half1, half2, ops(script.OpOR), drop) },
		"XOR 2x49 MB":                   func() []byte { return cat(half1, half2, ops(script.OpXOR), drop) },
		"EQUAL 2x49 MB":                 func() []byte { return cat(half1, half1, ops(script.OpEQUAL), drop) },
		"CAT 2x49 MB":                   func() []byte { return cat(half1, half2, ops(script.OpCAT), drop) },
		"DUP 49 MB":                     func() []byte { return cat(half1, ops(script.OpDUP, script.OpDROP), drop) },
		"BIN2NUM 32,000,000 bytes to 1": func() []byte { return cat(pushData4(padded), ops(script.OpBIN2NUM), drop) },
		"WITHIN 3x32,000,000 bytes": func() []byte {
			return cat(num1, num2, pushData4(fill(32_000_000, 17)), ops(script.OpWITHIN), drop)
		},
		"ROLL 149,980 deep": func() []byte { return cat(repeat(script.Op1, 149_990), dataPush(le(149_980)), ops(script.OpROLL)) },
	} {
		timeEngine(t, name, build(), nil)
	}
	for _, op := range []byte{script.Op1ADD, script.OpNEGATE, script.OpABS, script.Op2DIV, script.Op2MUL, script.OpNOT, script.OpRSHIFTNUM} {
		arg := []byte{}
		if op == script.OpRSHIFTNUM {
			arg = ops(script.Op1)
		}
		timeEngine(t, "0x"+hex2(op)+" on 32,000,000 bytes", cat(num1, arg, ops(op), drop), nil)
	}
	for _, op := range []byte{script.OpADD, script.OpSUB, script.OpMAX, script.OpNUMEQUAL, script.OpLESSTHAN, script.OpBOOLAND} {
		timeEngine(t, "0x"+hex2(op)+" on 2x32,000,000 bytes", cat(num1, num2, ops(op), drop), nil)
	}
	timeEngine(t, "PICK index of 32,000,000 bytes", cat(ops(script.Op1), num1, ops(script.OpPICK), drop), nil)
	timeEngine(t, "LSHIFTNUM 1 by 255,999,000", cat(ops(script.Op1), dataPush(le(255_999_000)), ops(script.OpLSHIFTNUM), drop), nil)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("heap obtained from the OS, at least the peak heap: %d MB", ms.HeapSys>>20)
}

// TestMeasureFindAndDelete times OP_CHECKMULTISIG at maxFindDeleteWork in
// three scriptCode shapes: all one-byte instructions, one large push, and
// 75-byte pushes.
func TestMeasureFindAndDelete(t *testing.T) {
	measuring(t)
	nops := repeat(script.OpNOP, 50_000)
	var pushes75 []byte
	for len(pushes75) < 1<<20 {
		pushes75 = append(pushes75, dataPush(make([]byte, 75))...)
		pushes75 = append(pushes75, script.OpDROP)
	}
	for name, code := range map[string][]byte{
		"50,000 one-byte instructions": nops,
		"one 16 MiB push":              cat(pushData4(fill(16<<20, 14)), ops(script.OpDROP)),
		"1 MiB of 75-byte pushes":      pushes75,
	} {
		lock := append(append([]byte{}, code...), script.OpCHECKMULTISIG)
		m := int(maxFindDeleteWork / (findDeleteWork(lock, 1) + 64))
		unlock := []byte{script.Op0}
		unlock = append(append(unlock, repeat(script.Op1, m)...), dataPush(le(m))...)
		unlock = append(append(unlock, repeat(script.Op1, m)...), dataPush(le(m))...)
		if err := check(lockSpend(lock, unlock), afterChronicle); err != nil {
			t.Fatalf("%s: %d signatures are refused: %v", name, m, err)
		}
		timeEngine(t, name+", "+uitoa(m)+" signatures (cap)", lock, unlock)
	}
}

// TestMeasureCheckSig times OP_CHECKSIG over the largest scriptCodes a
// 16 MiB submission holds, and the debugger's State overhead.
func TestMeasureCheckSig(t *testing.T) {
	measuring(t)
	priv, _ := ec.NewPrivateKey()
	sig, _ := priv.Sign(make([]byte, 32))
	sigB, pub := append(sig.Serialize(), 0x41), priv.PubKey().Compressed()
	code := cat(pushData4(fill(16<<20, 15)), ops(script.OpDROP))
	timeEngine(t, "CHECKSIG over a 16 MiB scriptCode", cat(code, dataPush(sigB), dataPush(pub), ops(script.OpCHECKSIG, script.OpDROP, script.Op1)), nil)
	s := lockSpend(cat(code, ops(script.Op1)), cat(code, dataPush(sigB), dataPush(pub), ops(script.OpCHECKSIG, script.OpDROP)))
	s.tx.Version = 2
	d := median(3, func() { _ = execute(s, afterChronicle) })
	t.Logf("%-44s %9.2f ms", "unlocking CHECKSIG over 16+16 MiB", float64(d.Microseconds())/1000)
}

// TestMeasureDebuggerOverhead times the engine with a no-op Debugger, the
// dry run the specification suggested: every hook gets a deep copy of the
// stacks and a copy of every parsed script (interpreter/state.go:61).
func TestMeasureDebuggerOverhead(t *testing.T) {
	measuring(t)
	timed := func(s spend, dbg interpreter.Debugger) time.Duration {
		return median(5, func() {
			opts := []interpreter.ExecutionOptionFunc{interpreter.WithTx(s.tx, s.vin, s.prevout), interpreter.WithFlags(afterChronicle)}
			if dbg != nil {
				opts = append(opts, interpreter.WithDebugger(dbg))
			}
			_ = interpreter.NewEngine().Execute(opts...)
		})
	}
	spends := honestSpends(t)
	spends["20,000 OP_NOP"] = lockSpend(append(repeat(script.OpNOP, 20_000), script.Op1), nil)
	spends["1 MiB push, 2,000 OP_NOP"] = lockSpend(cat(pushData4(fill(1<<20, 16)), repeat(script.OpNOP, 2000)), nil)
	for name, s := range spends {
		plain, hooked := timed(s, nil), timed(s, nopDebugger{})
		t.Logf("%-26s engine %10.1f us, with a no-op debugger %12.1f us", name,
			float64(plain.Nanoseconds())/1000, float64(hooked.Nanoseconds())/1000)
	}
}

// TestMeasureCheckMemory reports, for each worst shape, the bytes Check
// allocates in all and the most the heap grew above its size before Check,
// sampled every 100 us while Check runs.
func TestMeasureCheckMemory(t *testing.T) {
	measuring(t)
	t.Logf("an element bound takes %d bytes", unsafe.Sizeof(elem{}))
	for name, s := range worstShapes() {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		done, peak := make(chan struct{}), make(chan uint64)
		go func() {
			var m runtime.MemStats
			p := before.HeapAlloc
			for {
				select {
				case <-done:
					peak <- p
					return
				case <-time.After(100 * time.Microsecond):
					runtime.ReadMemStats(&m)
					p = max(p, m.HeapAlloc)
				}
			}
		}()
		err := check(s, afterChronicle)
		close(done)
		p := <-peak
		runtime.ReadMemStats(&after)
		t.Logf("%-40s allocated %7.1f MB, heap grew at most %6.1f MB (refused: %v)", name,
			float64(after.TotalAlloc-before.TotalAlloc)/1e6, float64(p-before.HeapAlloc)/1e6, err != nil)
	}
}

func hex2(b byte) string { return string([]byte{"0123456789abcdef"[b>>4], "0123456789abcdef"[b&15]}) }

func itoa(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return uitoa(n>>20) + " MiB"
	case n >= 1<<10 && n%(1<<10) == 0:
		return uitoa(n>>10) + " KiB"
	}
	return uitoa(n)
}

func uitoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
