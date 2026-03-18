package brc

import "github.com/bsv-blockchain/go-sdk/overlay"

// BRC-43 invoice number constants for key derivation.
// Uses canonical protocol IDs from go-sdk/overlay.
const (
	InvoiceSHIP      = "2-" + string(overlay.ProtocolIDSHIP) + "-1"
	InvoiceSLAP      = "2-" + string(overlay.ProtocolIDSLAP) + "-1"
	InvoiceHandshake = "2-relay-handshake-1" // custom mesh-specific (no BRC defines this)
)
