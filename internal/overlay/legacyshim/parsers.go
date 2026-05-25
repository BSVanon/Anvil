package legacyshim

import (
	"encoding/json"
	"fmt"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
)

// DefaultParsers returns the canonical lookup-service → script-parser
// mapping. Each parser is a thin wrapper around the topic package's
// exported parser (renamed from private in W-3 phase B) that returns
// the parsed entry marshalled as JSON, ready to drop into the legacy
// AdmittedOutput.Metadata field.
//
// If a topic later adds a new lookup service, register its parser here
// (and add a unit test asserting the metadata shape matches what apps
// currently depend on).
func DefaultParsers() map[string]ScriptParser {
	return map[string]ScriptParser{
		topics.UHRPLookupServiceName: func(scriptBytes []byte) (json.RawMessage, error) {
			entry := topics.ParseUHRPOutput(scriptBytes)
			if entry == nil {
				return nil, nil
			}
			return marshalEntry(entry)
		},
		topics.DEXSwapLookupServiceName: func(scriptBytes []byte) (json.RawMessage, error) {
			entry := topics.ParseDEXSwapMetadata(scriptBytes)
			if entry == nil {
				return nil, nil
			}
			return marshalEntry(entry)
		},
		topics.OrdLockLookupServiceName: func(scriptBytes []byte) (json.RawMessage, error) {
			entry := topics.ParseOrdLockScript(scriptBytes)
			if entry == nil {
				return nil, nil
			}
			return marshalEntry(entry)
		},
		topics.OrdLockBuyLookupServiceName: func(scriptBytes []byte) (json.RawMessage, error) {
			entry := topics.ParseOrdLockBuyScript(scriptBytes)
			if entry == nil {
				return nil, nil
			}
			return marshalEntry(entry)
		},
	}
}

func marshalEntry(v interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("legacyshim: marshal entry: %w", err)
	}
	return b, nil
}

// DefaultServiceTopics returns the canonical lookup-service → topics
// mapping for Anvil's four built-in services. Surfaced on
// GET /overlay/services. Mirrors what
// internal/overlay/handlers.go:135-143 returned before the shim took
// over, so apps relying on `service.topics` keep working unchanged.
//
// Each Anvil canonical lookup indexes exactly one topic by design (the
// service name and topic name are paired by convention: ls_uhrp ↔
// tm_uhrp, etc.). If a future deployment registers a multi-topic
// service, override this map in the Shim construction.
func DefaultServiceTopics() map[string][]string {
	return map[string][]string{
		topics.UHRPLookupServiceName:       {topics.UHRPTopicName},
		topics.DEXSwapLookupServiceName:    {topics.DEXSwapTopicName},
		topics.OrdLockLookupServiceName:    {topics.OrdLockTopicName},
		topics.OrdLockBuyLookupServiceName: {topics.OrdLockBuyTopicName},
	}
}
