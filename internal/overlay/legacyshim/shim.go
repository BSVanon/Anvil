// Package legacyshim translates Anvil's legacy /overlay/{submit,query,
// topics,services} HTTP surface into calls against the canonical v3
// engine (`go-overlay-services`). Implements Lens 2 = 2c (indefinite
// app-layer adapter) from docs/internal/OVERLAY_PROTOCOL_ALIGNMENT_PLAN.md:
// apps that haven't migrated to canonical /submit + /lookup keep working
// against /overlay/* while the canonical engine is the only data source
// underneath.
//
// SCOPE CARVE-OUT (Codex review 14a2d703): this package handles only the
// four legacy *overlay protocol* routes. The mesh-discovery routes that
// share the /overlay/ URL prefix — /overlay/lookup, /overlay/register,
// /overlay/deregister — are NOT in scope; they live in internal/api/
// server.go and stay registered there indefinitely (they have no
// canonical equivalent because they're Anvil-mesh-specific).
//
// Decommission: this package gets removed in W-9 when telemetry shows a
// 30-day quiet period on /overlay/{submit,query}. Not before.
package legacyshim

import (
	"encoding/json"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// Shim owns the legacy HTTP handlers. It is constructed once at boot
// and wraps the canonical engine + a per-lookup-service parser table
// used to reconstruct the legacy AdmittedOutput.Metadata field from the
// BEEF the canonical engine returns. Without that table the shim would
// have to drop Metadata entirely, which would break Anvil-Swap's
// discovery code (per docs/internal/APP_MIGRATION_TODO.md).
type Shim struct {
	Engine *engine.Engine

	// Parsers maps lookup-service name → ScriptParser that recovers the
	// per-output metadata Anvil legacy callers expect on
	// LookupAnswer.Outputs[i].Metadata. The defaults from the topics
	// package are wired in by DefaultParsers().
	Parsers map[string]ScriptParser

	// ServiceTopics maps lookup-service name → list of topic names that
	// service indexes. Surfaced on GET /overlay/services per the legacy
	// contract (internal/overlay/handlers.go:135-143) and the TS SDK
	// public type, which both include a required `topics` array. Wired
	// by DefaultServiceTopics() for the four Anvil canonical services;
	// boot code may override for custom deployments.
	ServiceTopics map[string][]string

	// MaxBodyBytes caps request body size on the legacy routes. Zero ⇒
	// default (64 MiB), matching the canonical Submit limit.
	MaxBodyBytes int64
}

// ScriptParser is the function signature for a single topic's
// locking-script parser. It receives the raw script bytes of an admitted
// output and returns a JSON blob suitable for the legacy
// LookupAnswer.Outputs[i].Metadata field. Returning nil with a nil error
// means "not a relevant script" — the shim treats that as "no metadata
// available" and omits the field rather than failing the whole query.
type ScriptParser func(scriptBytes []byte) (json.RawMessage, error)

const defaultMaxBodyBytes = 64 << 20 // 64 MiB

// maxBody returns the configured request body cap, falling back to the
// default.
func (s *Shim) maxBody() int64 {
	if s.MaxBodyBytes <= 0 {
		return defaultMaxBodyBytes
	}
	return s.MaxBodyBytes
}
