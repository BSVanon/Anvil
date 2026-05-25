// Package canonical implements Anvil's BRC-conformant overlay HTTP surface.
// It mirrors the route shapes exercised by the ts-stack conformance vectors
// at docs/internal/conformance-vectors/overlay/ — `POST /submit`, `POST /lookup`,
// `GET /health`, etc. — and lives alongside (not instead of) Anvil's legacy
// `/overlay/*` handlers in internal/overlay/handlers.go.
//
// Each workstream of the alignment plan fills in another slice of this package:
//   - Workstream A: health + auth (BRC-31)
//   - Workstream B: /submit pipeline
//   - Workstream C: /lookup + provider hydration
//   - Workstream D: SHIP/SLAP admin routes
//   - Workstream E: GASP sync endpoints
//
// See docs/internal/OVERLAY_PROTOCOL_ALIGNMENT_PLAN.md.
package canonical

import "net/http"

// Config is the wiring surface for the canonical overlay routes. Every
// callback returns live data from the host Anvil node; the canonical package
// holds no engine state of its own.
type Config struct {
	// NodeName is the operator-supplied node label exposed in /health and
	// /admin/config.
	NodeName string

	// Network is the short network name expected by the conformance vectors
	// ("main", "test", "local"). Empty means main.
	Network string

	// AdminIdentityKey is the 66-char hex pubkey of the configured admin
	// identity, or "" when no admin identity is configured. Exposed via
	// /admin/config; empty string serializes as JSON null.
	AdminIdentityKey string

	// Ready returns true when the node is fully initialized and accepting
	// traffic. Used by /health and /health/ready. If nil, treated as always
	// ready (suitable for tests that don't model readiness).
	Ready func() bool

	// TopicManagerCount returns the number of topic managers the engine has
	// registered. If nil, /health reports 0.
	TopicManagerCount func() int

	// LookupServiceCount returns the number of lookup services the engine has
	// registered. If nil, /health reports 0.
	LookupServiceCount func() int

	// TopicManagerNames returns the names of registered topic managers. Used
	// by /admin/stats. If nil, an empty list is reported.
	TopicManagerNames func() []string

	// LookupServiceNames returns the names of registered lookup services.
	// Used by /admin/stats. If nil, an empty list is reported.
	LookupServiceNames func() []string

	// AdminBearerToken is the Bearer token /admin/stats accepts via the
	// Authorization header. Empty string disables admin-protected routes
	// (all such requests return 401).
	AdminBearerToken string

	// ArcIngest is invoked by POST /arc-ingest after request validation
	// (txid present, body decoded). Implementations notify the overlay
	// engine of the mined transaction + Merkle proof. Returning a non-nil
	// error causes the handler to respond 500 ERR_ARC_INGEST_FAILED.
	//
	// If nil, the handler acknowledges (200) without forwarding — this is
	// suitable for the conformance runner and for read-only deployments,
	// but production Anvil MUST wire this to engine.OnArcIngest or
	// equivalent. Codex review 9fe46aca flagged that a nil hook in
	// production would silently drop ARC callbacks.
	ArcIngest func(req ArcIngestRequest) error

	// Submit is invoked by POST /submit after header + body validation.
	// Implementations parse BEEF, run topic manager admission, and return
	// the resulting STEAK. Returning a non-nil error responds 500
	// ERR_SUBMIT_FAILED.
	//
	// If nil, the handler returns a generic STEAK with empty admissions
	// per requested topic (conformance-runner / no-engine path). Production
	// Anvil MUST wire this; same caveat as ArcIngest.
	Submit func(req SubmitRequest) (SubmitResponse, error)

	// KnownTopics, if set, returns the list of topic manager names the
	// node hosts. /submit uses it to reject submissions targeting unknown
	// topics with 400 ERR_UNKNOWN_TOPIC (vector overlay.submit.7). When
	// nil, all topics are accepted at the route boundary and deferred to
	// the Submit callback.
	KnownTopics func() []string

	// Auth wires BRC-31 behavior for /.well-known/auth and the AuthMiddleware
	// applied to other routes. Zero-value AuthConfig is acceptable for Pass 1.
	Auth AuthConfig
}

func (c Config) resolveTopicNames() []string {
	if c.TopicManagerNames == nil {
		return []string{}
	}
	return c.TopicManagerNames()
}

func (c Config) resolveLookupNames() []string {
	if c.LookupServiceNames == nil {
		return []string{}
	}
	return c.LookupServiceNames()
}

// New returns an http.Handler hosting the canonical overlay routes. The
// returned handler can be mounted on its own (e.g. by the conformance runner)
// or composed into a larger Anvil mux.
//
// Routes registered today (Workstreams A + B):
//   - GET /health
//   - GET /health/live
//   - GET /health/ready
//   - GET /admin/config
//   - GET /admin/stats (Bearer-protected)
//   - POST /.well-known/auth (BRC-31 Phase 1)
//   - POST /arc-ingest
//   - POST /submit (BRC-22)
//
// Additional routes will be registered as each workstream lands.
func New(cfg Config) http.Handler {
	mux := http.NewServeMux()
	registerHealth(mux, cfg)
	registerAdminConfig(mux, cfg)
	registerAdminStats(mux, cfg)
	registerAuth(mux, cfg.Auth)
	registerArcIngest(mux, cfg)
	registerSubmit(mux, cfg)
	return mux
}

// Register attaches the canonical routes to an existing mux. Use this from
// cmd/anvil/main.go so the production Anvil node serves canonical routes on
// the same listener as legacy `/overlay/*`.
func Register(mux *http.ServeMux, cfg Config) {
	registerHealth(mux, cfg)
	registerAdminConfig(mux, cfg)
	registerAdminStats(mux, cfg)
	registerAuth(mux, cfg.Auth)
	registerArcIngest(mux, cfg)
	registerSubmit(mux, cfg)
}

// resolveReady applies the "nil means always ready" default.
func (c Config) resolveReady() bool {
	if c.Ready == nil {
		return true
	}
	return c.Ready()
}

// resolveNetwork applies the "empty means main" default.
func (c Config) resolveNetwork() string {
	if c.Network == "" {
		return "main"
	}
	return c.Network
}

func (c Config) resolveTopicCount() int {
	if c.TopicManagerCount == nil {
		return 0
	}
	return c.TopicManagerCount()
}

func (c Config) resolveLookupCount() int {
	if c.LookupServiceCount == nil {
		return 0
	}
	return c.LookupServiceCount()
}
