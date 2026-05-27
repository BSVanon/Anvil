package topics

import (
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
)

// canonicalVersion is the W-2 adapter version stamp. Bumped if the adapter
// translation changes shape in a way consumers might care about. Distinct
// from Anvil's release version because it tracks adapter behaviour, not
// node behaviour.
const canonicalVersion = "1.0.0"

// UHRPCanonical returns the canonical engine.TopicManager for UHRP
// (tm_uhrp). The name comes from UHRPTopicName so changing the canonical
// identifier in uhrp.go automatically propagates to the engine
// registration.
func UHRPCanonical() engine.TopicManager {
	return NewAdapter(UHRPTopicName, NewUHRPTopicManager(), &overlay.MetaData{
		Name:        UHRPTopicName,
		Description: "UHRP (BRC-26) content availability advertisements",
		Version:     canonicalVersion,
	})
}

// DEXSwapCanonical returns the canonical engine.TopicManager for DEX swap
// (tm_dex_swap).
func DEXSwapCanonical() engine.TopicManager {
	return NewAdapter(DEXSwapTopicName, NewDEXSwapTopicManager(), &overlay.MetaData{
		Name:        DEXSwapTopicName,
		Description: "BRC-79 DEX swap bid covenants",
		Version:     canonicalVersion,
	})
}

// OrdLockCanonical returns the canonical engine.TopicManager for OrdLock
// listings (tm_ordlock_listings).
func OrdLockCanonical() engine.TopicManager {
	return NewAdapter(OrdLockTopicName, NewOrdLockTopicManager(), &overlay.MetaData{
		Name:        OrdLockTopicName,
		Description: "OrdLock listing covenants (Anvil v2.3.1 topic)",
		Version:     canonicalVersion,
	})
}

// OrdLockBuyCanonical returns the canonical engine.TopicManager for OrdLock
// buy-side vaults (tm_ordlock_buy_vaults).
func OrdLockBuyCanonical() engine.TopicManager {
	return NewAdapter(OrdLockBuyTopicName, NewOrdLockBuyTopicManager(), &overlay.MetaData{
		Name:        OrdLockBuyTopicName,
		Description: "OrdLock buy-side vault covenants",
		Version:     canonicalVersion,
	})
}

// UMPCanonical returns the canonical engine.TopicManager for the User
// Management Protocol (tm_users). Hosted in Anvil today as a pragmatic
// transitional placement — see ump.go header for the upstream
// destination + port notes.
func UMPCanonical() engine.TopicManager {
	return NewAdapter(UMPTopicName, NewUMPTopicManager(), &overlay.MetaData{
		Name:        UMPTopicName,
		Description: "UMP (User Management Protocol) account-descriptor tokens",
		Version:     canonicalVersion,
	})
}

// IdentityCanonical returns the canonical engine.TopicManager for the
// BRC-52 identity certificate publication topic (tm_identity). Same
// transitional placement note as UMPCanonical applies.
func IdentityCanonical() engine.TopicManager {
	return NewAdapter(IdentityTopicName, NewIdentityTopicManager(), &overlay.MetaData{
		Name:        IdentityTopicName,
		Description: "BRC-52 verifiable identity certificate publication",
		Version:     canonicalVersion,
	})
}

// KVStoreCanonical returns the canonical engine.TopicManager for the
// BRC-35 key-value store publication topic (tm_kvstore). Same
// transitional placement note as UMPCanonical applies.
func KVStoreCanonical() engine.TopicManager {
	return NewAdapter(KVStoreTopicName, NewKVStoreTopicManager(), &overlay.MetaData{
		Name:        KVStoreTopicName,
		Description: "BRC-35 canonical key-value record publication",
		Version:     canonicalVersion,
	})
}
