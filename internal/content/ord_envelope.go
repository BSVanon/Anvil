package content

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// OrdEnvelope is a well-formed 1Sat inscription envelope (BRC-160) found in
// an output's locking script.
type OrdEnvelope struct {
	// ContentType is field 1, the MIME type; "" when the envelope has none.
	ContentType string
	// Body is field 0, the content bytes. It may be empty, never nil.
	Body []byte
	// Parent is field 3's binary outpoint: a 32-byte transaction ID and an
	// optional 4-byte little-endian output index. It aliases the script.
	Parent []byte
	// ParentSet distinguishes an empty field-3 value from an absent field.
	ParentSet bool
}

// ParseOrdEnvelope returns the first well-formed "ord" envelope in a locking
// script, following BRC-160's envelope rules:
//
//   - the envelope is OP_FALSE OP_IF <"ord"> followed by field/value pairs,
//     and may sit anywhere in the script. The script is walked op by op, so
//     bytes inside some other push are never read as an envelope;
//   - a field tag is OP_0 to OP_16 or a single-byte push, so a single-byte
//     push of 0x00 or 0x01 is the same field as OP_0 or OP_1. A wider push
//     or OP_1NEGATE is an unknown field;
//   - each value is exactly one push. Values are never joined across pushes;
//   - field 1 is the content type, field 3 is a 32- or 36-byte parent
//     outpoint, and each field's last occurrence wins. Unknown fields are
//     skipped;
//   - field 0, the body, which may be empty, ends the field list, and the
//     next op must be OP_ENDIF.
//
// A candidate that breaks a rule is not an envelope. The walk then goes on
// past its "ord" push, so a malformed candidate does not hide a well-formed
// envelope later in the same script. The returned body aliases s.
func ParseOrdEnvelope(s []byte) (OrdEnvelope, bool) {
	scr := script.Script(s)
	var before [2]byte // the two ops before the current one
	seen := 0
	for pos := 0; pos < len(scr); {
		op, err := scr.ReadOp(&pos)
		if err != nil {
			// The rest is not a sequence of ops (data after OP_RETURN, say),
			// so no envelope can start in it.
			return OrdEnvelope{}, false
		}
		if seen == 2 && before[0] == script.OpFALSE && before[1] == script.OpIF &&
			op.Op == script.OpDATA3 && string(op.Data) == "ord" {
			if env, ok := parseOrdFields(&scr, pos); ok {
				return env, true
			}
		}
		before[0], before[1] = before[1], op.Op
		if seen < 2 {
			seen++
		}
	}
	return OrdEnvelope{}, false
}

// parseOrdFields reads the field/value pairs that follow an "ord" push at
// pos, up to and including the OP_ENDIF after the body.
func parseOrdFields(scr *script.Script, pos int) (OrdEnvelope, bool) {
	var env OrdEnvelope
	for {
		tag, err := scr.ReadOp(&pos)
		if err != nil {
			return OrdEnvelope{}, false
		}
		field, ok := ordFieldTag(tag)
		if !ok {
			// Not a push, OP_ENDIF before any body included: BRC-160 makes
			// the body a required field.
			return OrdEnvelope{}, false
		}
		value, err := scr.ReadOp(&pos)
		if err != nil || !isPushOp(value.Op) {
			return OrdEnvelope{}, false
		}
		switch field {
		case 0, 1:
			// A small-number op carries no bytes of its own here, so the
			// two fields Anvil reads must be data pushes.
			if value.Op > script.OpPUSHDATA4 {
				return OrdEnvelope{}, false
			}
		}
		switch field {
		case 0:
			end, err := scr.ReadOp(&pos)
			if err != nil || end.Op != script.OpENDIF {
				return OrdEnvelope{}, false
			}
			env.Body = value.Data
			if env.Body == nil {
				env.Body = []byte{}
			}
			if env.ParentSet && len(env.Parent) != 32 && len(env.Parent) != 36 {
				return OrdEnvelope{}, false
			}
			return env, true
		case 1:
			env.ContentType = string(value.Data)
		case 3:
			env.Parent, env.ParentSet = value.Data, true
		}
	}
}

// ParseOrdEnvelopeAt parses output vout and enforces BRC-160's parent proof:
// when field 3 claims a parent outpoint, the creating transaction must spend
// that exact outpoint.
func ParseOrdEnvelopeAt(tx *transaction.Transaction, vout int) (OrdEnvelope, bool) {
	if tx == nil || vout < 0 || vout >= len(tx.Outputs) || tx.Outputs[vout].LockingScript == nil {
		return OrdEnvelope{}, false
	}
	env, ok := ParseOrdEnvelope(tx.Outputs[vout].LockingScript.Bytes())
	if !ok || !env.ParentSet {
		return env, ok
	}
	parentVout := uint32(0)
	if len(env.Parent) == 36 {
		parentVout = binary.LittleEndian.Uint32(env.Parent[32:])
	}
	for _, in := range tx.Inputs {
		if in.SourceTXID != nil && in.SourceTxOutIndex == parentVout &&
			string(in.SourceTXID.CloneBytes()) == string(env.Parent[:32]) {
			return env, true
		}
	}
	return OrdEnvelope{}, false
}

func parseOrdEnvelopeTx(raw []byte, vout int) (OrdEnvelope, bool, error) {
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return OrdEnvelope{}, false, err
	}
	env, ok := ParseOrdEnvelopeAt(tx, vout)
	return env, ok, nil
}

// ordFieldTag returns the field number op names, or -1 for an unknown
// field written as a wider push or OP_1NEGATE. ok is false when op is no
// push at all.
func ordFieldTag(op *script.ScriptChunk) (field int, ok bool) {
	switch {
	case op.Op == script.Op0:
		return 0, true
	case op.Op >= script.Op1 && op.Op <= script.Op16:
		return int(op.Op-script.Op1) + 1, true
	case op.Op <= script.OpPUSHDATA4 && len(op.Data) == 1:
		return int(op.Data[0]), true
	case isPushOp(op.Op):
		return -1, true
	default:
		return 0, false
	}
}

// isPushOp reports whether op pushes data: OP_0, a data push, OP_1NEGATE or
// OP_1 to OP_16.
func isPushOp(op byte) bool {
	return op <= script.Op16 && op != script.OpRESERVED
}
