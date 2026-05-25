// Package v3engine wires Anvil's canonical-engine pieces (storage adapter,
// topic adapters, lookup services, chain tracker) into a single
// engine.Engine instance ready for HTTP route handlers. This is the W-5
// integration layer: it owns no business logic, only the construction
// glue + the canonical-route HTTP handlers (handlers.go).
//
// The package name v3engine reflects Anvil's v3.0.0 target release (when
// W-8 ships) and distinguishes from the legacy bridge code at
// internal/overlay/canonical/ that gets decommissioned in W-7.
package v3engine

import (
	"errors"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/ship"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/slap"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// Config holds the construction inputs for the canonical Anvil engine.
//
// Storage is required: the engine's Submit/Lookup pipeline calls into
// every method of engine.Storage and panics on nil access.
//
// HeadersStore is required because the engine validates BEEF merkle
// proofs via go-sdk's SPV verifier, which needs a ChainTracker. Anvil's
// existing *headers.Store satisfies the chaintracker.ChainTracker
// contract directly (see internal/headers/store.go IsValidRootForHeight
// + CurrentHeight), so no adapter is needed.
//
// LookupDB is the LevelDB handle the lookup services use for their own
// per-service indexes (lk_uhrp:, lk_dexswap:, lk_ordlock:, lk_ordlockbuy:).
// May be the same handle as the storage adapter's underlying database
// or a separate one; the key-family prefixes guarantee non-collision.
//
// HostingURL is the public URL where Anvil serves canonical routes;
// surfaces in the engine's SHIP/SLAP advertisement responses. Empty
// string is allowed for offline/test setups.
//
// W-10.3 federation fields are all optional. Leaving them nil keeps the
// pre-W-10 single-node behavior: no SHIP/SLAP advertising, no GASP sync,
// no peer discovery. Operators that want canonical BRC-88 federation
// populate them; cmd/anvil/main.go wires them when
// cfg.Overlay.EnableGASPSync is true.
//
// Nil-safety scope: the upstream Engine guards on *nil Advertiser*
// (SyncAdvertisements returns early at engine.go:894) and on empty
// SyncConfiguration (StartGASPSync iterates an empty map). It does NOT
// tolerate a non-nil Advertiser whose FindAllAdvertisements returns an
// error — SyncAdvertisements propagates that error and aborts.
// Therefore the federation.Advertiser ErrUnimplemented stub MUST stay
// unwired (Advertiser field nil) until W-10.2 fills in the four
// methods; setting it before then would break advertisement sync.
type Config struct {
	Storage      *anvilstorage.Storage
	HeadersStore *headers.Store
	LookupDB     *leveldb.DB
	HostingURL   string

	// Advertiser publishes/revokes/parses SHIP+SLAP advertisements on
	// behalf of this node. Nil disables auto-advertising. See
	// internal/overlay/federation/ for Anvil's implementation, built on
	// go-sdk's canonical admin-token PushDrop template.
	Advertiser advertiser.Advertiser
	// SyncConfiguration is the per-topic GASP policy map. Empty/nil
	// disables GASP sync. Typical setup: every active topic gets
	// {Type: SyncConfigurationSHIP} so peers are discovered via SLAP
	// lookup at sync time.
	SyncConfiguration map[string]engine.SyncConfiguration
	// SHIPTrackers / SLAPTrackers are bootstrap URLs the lookup
	// resolver queries when discovering peers via SHIP/SLAP. Empty
	// disables external discovery (engine still serves inbound GASP
	// requests).
	SHIPTrackers []string
	SLAPTrackers []string
	// LookupResolver queries external overlay nodes for SHIP/SLAP
	// advertisements; required if SyncConfiguration uses SHIP-type
	// discovery. Anvil supplies a go-sdk-backed canonical resolver.
	LookupResolver engine.LookupResolverProvider
	// Broadcaster propagates submitted transactions to the wider
	// network (ARC etc.). Required if the engine is expected to publish
	// SHIP/SLAP advertisements on-chain or relay admitted transactions.
	// Anvil's existing internal/broadcaster satisfies this interface.
	Broadcaster transaction.Broadcaster
	// SHIPStorage / SLAPStorage are optional pre-constructed local
	// adapters for the canonical SHIP/SLAP topic managers + lookup
	// services. Production wiring in cmd/anvil/main.go constructs these
	// once and shares them between v3engine.New (for tm_ship/tm_slap
	// admission + ls_ship/ls_slap queries) and federation.NewAdvertiser
	// (for outbound CreateAdvertisements/FindAllAdvertisements/Revoke).
	// Nil triggers a default construction from LookupDB inside
	// v3engine.New — useful for tests and callers that don't operate
	// the federation Advertiser separately.
	SHIPStorage *federation.SHIPStorage
	SLAPStorage *federation.SLAPStorage
}

// New constructs an engine.Engine wired with Anvil's four canonical
// topic adapters and four canonical lookup services. Returns an error
// rather than panicking on missing required Config fields so callers
// (cmd/anvil/main.go, integration tests) can fail loudly at boot.
//
// Federation surfaces (Advertiser, SyncConfiguration, SHIPTrackers,
// SLAPTrackers, LookupResolver, Broadcaster) are passed through
// transparently. Leaving them nil produces a single-node engine — no
// SHIP/SLAP advertising, no GASP peer discovery, no transaction
// propagation. The upstream Engine guards every federation pathway on
// nil. Populating them enables canonical BRC-88 federation; see W-10
// federation plan (docs/internal/W10_FEDERATION_PLAN.md) for the
// full operator wiring.
//
// BroadcastFacilitator remains unset; Anvil doesn't currently use the
// canonical topic-broadcaster facilitator pattern.
func New(cfg *Config) (*engine.Engine, error) {
	if cfg == nil {
		return nil, errors.New("v3engine: nil config")
	}
	if cfg.Storage == nil {
		return nil, errors.New("v3engine: nil storage")
	}
	if cfg.HeadersStore == nil {
		return nil, errors.New("v3engine: nil headers store")
	}
	if cfg.LookupDB == nil {
		return nil, errors.New("v3engine: nil lookup db")
	}

	managers := map[string]engine.TopicManager{
		topics.UHRPTopicName:       topics.UHRPCanonical(),
		topics.DEXSwapTopicName:    topics.DEXSwapCanonical(),
		topics.OrdLockTopicName:    topics.OrdLockCanonical(),
		topics.OrdLockBuyTopicName: topics.OrdLockBuyCanonical(),
		// W-10.1: canonical-upstream primitives (UMP, Identity). Hosted
		// in Anvil today as a pragmatic transitional placement —
		// destined for go-overlay-discovery-services once that repo
		// gains a topic-impl partition. See topics/ump.go +
		// topics/identity.go headers for port provenance.
		topics.UMPTopicName:      topics.UMPCanonical(),
		topics.IdentityTopicName: topics.IdentityCanonical(),
	}

	lookupServices := map[string]engine.LookupService{
		topics.UHRPLookupServiceName:       lookups.NewUHRPLookupService(cfg.LookupDB),
		topics.DEXSwapLookupServiceName:    lookups.NewDEXSwapLookupService(cfg.LookupDB),
		topics.OrdLockLookupServiceName:    lookups.NewOrdLockLookupService(cfg.LookupDB),
		topics.OrdLockBuyLookupServiceName: lookups.NewOrdLockBuyLookupService(cfg.LookupDB),
		topics.UMPLookupServiceName:        lookups.NewUMPLookupService(cfg.LookupDB),
		topics.IdentityLookupServiceName:   lookups.NewIdentityLookupService(cfg.LookupDB),
	}

	// Canonical BRC-88 SHIP/SLAP topic managers + lookup services from
	// bsv-blockchain/go-overlay-discovery-services. Storage is Anvil's
	// LevelDB-backed adapter from internal/overlay/federation. The
	// canonical TopicManagers index inbound advertisements; the
	// LookupServices answer ls_ship / ls_slap queries. Both are always
	// registered — federation participation is gated downstream by
	// the Advertiser + LookupResolver wiring in Config.
	//
	// SHIPStorage + SLAPStorage may be supplied by the caller (typical
	// production wiring in cmd/anvil/main.go, where the federation
	// Advertiser also references them) or constructed here from
	// cfg.LookupDB (test wiring + backwards compat for callers that
	// just want the engine without separate federation plumbing).
	shipStore := cfg.SHIPStorage
	if shipStore == nil {
		shipStore = federation.NewSHIPStorage(cfg.LookupDB)
	}
	slapStore := cfg.SLAPStorage
	if slapStore == nil {
		slapStore = federation.NewSLAPStorage(cfg.LookupDB)
	}
	shipLookup := ship.NewLookupService(shipStore)
	slapLookup := slap.NewLookupService(slapStore)
	managers[ship.Topic] = ship.NewTopicManager(shipStore, shipLookup)
	managers[slap.Topic] = slap.NewTopicManager(slapStore, slapLookup)
	lookupServices[ship.Service] = shipLookup
	lookupServices[slap.Service] = slapLookup

	// headers.Store satisfies chaintracker.ChainTracker directly
	// (IsValidRootForHeight + CurrentHeight at the expected signatures);
	// no adapter needed.
	eng := engine.NewEngine(&engine.Config{
		Managers:          managers,
		LookupServices:    lookupServices,
		Storage:           cfg.Storage,
		ChainTracker:      cfg.HeadersStore,
		HostingURL:        cfg.HostingURL,
		Advertiser:        cfg.Advertiser,
		SyncConfiguration: cfg.SyncConfiguration,
		SHIPTrackers:      cfg.SHIPTrackers,
		SLAPTrackers:      cfg.SLAPTrackers,
		LookupResolver:    cfg.LookupResolver,
		Broadcaster:       cfg.Broadcaster,
	})
	return eng, nil
}
