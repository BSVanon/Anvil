package brc

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
)

// TokenFields holds the parsed fields from a BRC-48 token script.
type TokenFields struct {
	Protocol      string
	IdentityPub   string
	Domain        string
	TopicProvider string         // "topic" for SHIP, "provider" for SLAP
	LockingPub    *ec.PublicKey  // locking public key from BRC-48 script
}

// ParseTokenScript extracts the data fields from a BRC-48 push-drop script
// using go-sdk's canonical pushdrop.Decode.
func ParseTokenScript(s *script.Script) (*TokenFields, error) {
	result := pushdrop.Decode(s)
	if result == nil {
		return nil, errInvalidScript
	}
	if len(result.Fields) < 4 {
		return nil, errTooFewFields
	}
	return &TokenFields{
		Protocol:      string(result.Fields[0]),
		IdentityPub:   string(result.Fields[1]),
		Domain:        string(result.Fields[2]),
		TopicProvider: string(result.Fields[3]),
		LockingPub:    result.LockingPublicKey,
	}, nil
}

// buildPushDropScript builds a BRC-48 push-drop script in lock-before format:
// [pubkey] [CHECKSIG] [field1] [field2] ... [2DROP...] [DROP]
// This is the format expected by go-sdk's pushdrop.Decode.
func buildPushDropScript(lockingPub *ec.PublicKey, fields [][]byte) (*script.Script, error) {
	var chunks []*script.ScriptChunk

	// Lock-before: pubkey + CHECKSIG first
	pubBytes := lockingPub.Compressed()
	chunks = append(chunks, &script.ScriptChunk{Op: byte(len(pubBytes)), Data: pubBytes})
	chunks = append(chunks, &script.ScriptChunk{Op: script.OpCHECKSIG})

	// Data fields
	for _, f := range fields {
		chunks = append(chunks, pushdrop.CreateMinimallyEncodedScriptChunk(f))
	}

	// Drop operations
	remaining := len(fields)
	for remaining > 1 {
		chunks = append(chunks, &script.ScriptChunk{Op: script.Op2DROP})
		remaining -= 2
	}
	if remaining > 0 {
		chunks = append(chunks, &script.ScriptChunk{Op: script.OpDROP})
	}

	return script.NewScriptFromScriptOps(chunks)
}

var (
	errInvalidScript = errorf("invalid BRC-48 script")
	errTooFewFields  = errorf("expected >= 4 fields in BRC-48 script")
)

type constantError string

func errorf(s string) constantError { return constantError(s) }
func (e constantError) Error() string { return string(e) }
