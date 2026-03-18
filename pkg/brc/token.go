package brc

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BRC-48 opcodes used in token scripts.
const (
	opDROP     = 0x75
	op2DROP    = 0x6d
	opCHECKSIG = 0xac
)

// pushData returns the Bitcoin push-data encoding for b.
func pushData(b []byte) []byte {
	l := len(b)
	switch {
	case l <= 75:
		return append([]byte{byte(l)}, b...)
	case l <= 255:
		return append([]byte{0x4c, byte(l)}, b...)
	case l <= 65535:
		return append([]byte{0x4d, byte(l), byte(l >> 8)}, b...)
	default:
		return append([]byte{0x4e, byte(l), byte(l >> 8), byte(l >> 16), byte(l >> 24)}, b...)
	}
}

// BuildTokenScript builds a BRC-48 locking script:
//
//	pushData(fields[0]) pushData(fields[1]) ... pushData(fields[n])
//	OP_DROP OP_2DROP OP_DROP
//	pushData(lockingPub) OP_CHECKSIG
func BuildTokenScript(fields []string, lockingPub *secp256k1.PublicKey) []byte {
	var buf bytes.Buffer
	for _, f := range fields {
		buf.Write(pushData([]byte(f)))
	}
	buf.WriteByte(opDROP)
	buf.WriteByte(op2DROP)
	buf.WriteByte(opDROP)
	buf.Write(pushData(lockingPub.SerializeCompressed()))
	buf.WriteByte(opCHECKSIG)
	return buf.Bytes()
}

// TokenFields holds the parsed fields from a BRC-48 token script.
type TokenFields struct {
	Protocol      string
	IdentityPub   string
	Domain        string
	TopicProvider string // "topic" for SHIP, "provider" for SLAP
	LockingPub    []byte // 33-byte compressed public key
}

// ParseTokenScript extracts the data fields and locking pubkey from a BRC-48
// script. Returns an error if the script doesn't match the expected format.
func ParseTokenScript(script []byte) (*TokenFields, error) {
	chunks, err := decodeScript(script)
	if err != nil {
		return nil, err
	}

	// Expect: 4 data pushes + OP_DROP + OP_2DROP + OP_DROP + pubkey push + OP_CHECKSIG
	if len(chunks) < 9 {
		return nil, fmt.Errorf("expected >= 9 script chunks, got %d", len(chunks))
	}

	// Validate opcode sequence
	opcodeIdx := 4
	if !chunks[opcodeIdx].isOp(opDROP) || !chunks[opcodeIdx+1].isOp(op2DROP) ||
		!chunks[opcodeIdx+2].isOp(opDROP) || !chunks[opcodeIdx+4].isOp(opCHECKSIG) {
		return nil, errors.New("invalid opcode sequence")
	}

	pubBytes := chunks[opcodeIdx+3].data
	if len(pubBytes) != 33 {
		return nil, fmt.Errorf("locking pubkey must be 33 bytes, got %d", len(pubBytes))
	}

	return &TokenFields{
		Protocol:      string(chunks[0].data),
		IdentityPub:   string(chunks[1].data),
		Domain:        string(chunks[2].data),
		TopicProvider: string(chunks[3].data),
		LockingPub:    pubBytes,
	}, nil
}

type scriptChunk struct {
	data   []byte
	op     byte
	opcode bool // true if this chunk is an opcode, not data
}

func (c scriptChunk) isOp(op byte) bool { return c.opcode && c.op == op }

func decodeScript(script []byte) ([]scriptChunk, error) {
	var chunks []scriptChunk
	i := 0
	for i < len(script) {
		op := script[i]
		i++
		switch {
		case op >= 1 && op <= 75:
			end := i + int(op)
			if end > len(script) {
				return nil, errors.New("pushdata overflows script")
			}
			chunks = append(chunks, scriptChunk{data: script[i:end]})
			i = end
		case op == 0x4c: // OP_PUSHDATA1
			if i >= len(script) {
				return nil, errors.New("missing pushdata1 length")
			}
			l := int(script[i])
			i++
			end := i + l
			if end > len(script) {
				return nil, errors.New("pushdata1 overflows script")
			}
			chunks = append(chunks, scriptChunk{data: script[i:end]})
			i = end
		case op == 0x4d: // OP_PUSHDATA2
			if i+1 >= len(script) {
				return nil, errors.New("missing pushdata2 length")
			}
			l := int(script[i]) | int(script[i+1])<<8
			i += 2
			end := i + l
			if end > len(script) {
				return nil, errors.New("pushdata2 overflows script")
			}
			chunks = append(chunks, scriptChunk{data: script[i:end]})
			i = end
		default:
			chunks = append(chunks, scriptChunk{op: op, opcode: true})
		}
	}
	return chunks, nil
}
