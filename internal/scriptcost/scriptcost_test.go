package scriptcost

import (
	"bytes"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
)

func push(n int) []byte {
	s := &script.Script{}
	_ = s.AppendPushData(bytes.Repeat([]byte{0x42}, n))
	return *s
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// scripts is a spread of well-formed and malformed scripts: every push form,
// an OP_RETURN at depth 0 and inside a conditional, and truncated pushes.
var scripts = map[string][]byte{
	"empty":            {},
	"p2pkh":            cat([]byte{script.OpDUP, script.OpHASH160}, push(20), []byte{script.OpEQUALVERIFY, script.OpCHECKSIG}),
	"pushdrop":         cat(push(33), []byte{script.OpCHECKSIG}, push(4), push(33), push(80), push(300), push(70000), []byte{script.Op2DROP, script.Op2DROP, script.OpDROP}),
	"op_return-data":   cat([]byte{script.OpFALSE, script.OpRETURN}, push(10), []byte{script.OpNOP, script.OpNOP, script.OpCAT}),
	"op_return-in-if":  cat([]byte{script.OpIF, script.OpRETURN, script.OpENDIF, script.OpNOP}, push(3)),
	"stray-endif":      {script.OpENDIF, script.OpRETURN, script.OpNOP, script.OpNOP},
	"nops":             bytes.Repeat([]byte{script.OpNOP}, 1000),
	"truncated-data":   {script.OpNOP, 0x05, 0x01, 0x02},
	"truncated-pd2":    {script.OpNOP, script.OpPUSHDATA2, 0x10},
	"truncated-pd4":    {script.OpPUSHDATA4, 0xff, 0xff, 0xff, 0xff, 0x00},
	"pd1-zero":         {script.OpPUSHDATA1, 0x00, script.OpNOP},
	"cat-after-return": cat([]byte{script.OpTRUE, script.OpRETURN, script.OpCAT}),
}

// TestChunks_MatchesDecodeScript: Chunks counts what script.DecodeScript
// returns, for a script it decodes, and stops where it fails.
func TestChunks_MatchesDecodeScript(t *testing.T) {
	for name, s := range scripts {
		want, err := script.DecodeScript(s)
		got := Chunks(s, 1<<30)
		if err != nil {
			if got != len(want) {
				t.Errorf("%s: Chunks = %d, DecodeScript failed after %d chunks", name, got, len(want))
			}
			continue
		}
		if got != len(want) {
			t.Errorf("%s: Chunks = %d, DecodeScript decoded %d", name, got, len(want))
		}
	}
}

// TestInstructions_MatchesNodeExactParse: Instructions counts every
// instruction, an OP_RETURN and what follows it included, as DecodeScript
// does when told to parse past OP_RETURN, plus one for a truncated push,
// which the interpreter keeps as a last, malformed instruction.
func TestInstructions_MatchesNodeExactParse(t *testing.T) {
	for name, s := range scripts {
		want, err := script.DecodeScript(s, script.DecodeOptionsParseOpReturn)
		n := len(want)
		if err != nil {
			n++
		}
		if got, _ := Instructions(s, 1<<30); got != n {
			t.Errorf("%s: Instructions = %d, want %d", name, got, n)
		}
	}
}

// TestInstructions_StopsPastTheLimit: the count stops one past the limit, so
// a caller's cap check costs no more than the cap.
func TestInstructions_StopsPastTheLimit(t *testing.T) {
	s := bytes.Repeat([]byte{script.OpNOP}, 10_000)
	if n, _ := Instructions(s, 100); n != 101 {
		t.Fatalf("Instructions over a limit of 100 = %d, want 101", n)
	}
	if n := Chunks(s, 100); n != 101 {
		t.Fatalf("Chunks over a limit of 100 = %d, want 101", n)
	}
}

// TestInstructions_FlagsOpcodesThatWriteNewElements: an opcode that can
// write a new stack element sets copies; pushes, stack moves, hashes and
// signature checks do not.
func TestInstructions_FlagsOpcodesThatWriteNewElements(t *testing.T) {
	for _, op := range []byte{script.OpCAT, script.OpSPLIT, script.OpNUM2BIN, script.OpBIN2NUM,
		script.OpINVERT, script.OpAND, script.OpOR, script.OpXOR, script.Op1ADD, script.OpADD,
		script.OpMUL, script.OpLSHIFT, script.OpRSHIFT, script.OpMIN, script.OpWITHIN, script.OpNOP4, script.OpNOP10} {
		if _, copies := Instructions([]byte{script.OpTRUE, script.OpTRUE, op}, 10); !copies {
			t.Errorf("opcode 0x%02x not flagged", op)
		}
	}
	for name, s := range map[string][]byte{"p2pkh": scripts["p2pkh"], "pushdrop": scripts["pushdrop"], "nops": scripts["nops"]} {
		if _, copies := Instructions(s, 1<<30); copies {
			t.Errorf("%s flagged as writing new elements", name)
		}
	}
	stack := []byte{script.OpDUP, script.Op2DUP, script.Op3DUP, script.OpOVER, script.Op2OVER, script.OpPICK,
		script.OpROLL, script.OpTUCK, script.OpSWAP, script.OpSHA256, script.OpHASH256, script.OpCHECKMULTISIG,
		script.OpSIZE, script.OpEQUAL, script.OpCHECKLOCKTIMEVERIFY, script.OpCHECKSEQUENCEVERIFY}
	if _, copies := Instructions(stack, 100); copies {
		t.Error("stack moves, hashes, signature checks or comparisons flagged")
	}
}
