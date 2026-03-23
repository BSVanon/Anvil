package topics

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay"
)

// UHRPLookupServiceName is the BRC-87 standard name for the UHRP lookup service.
const UHRPLookupServiceName = "ls_uhrp"

// UHRPLookupQuery is the query format for the UHRP lookup service.
type UHRPLookupQuery struct {
	// ContentHash resolves a specific file by its SHA-256 hash.
	ContentHash string `json:"content_hash,omitempty"`
	// List returns all UHRP entries. Values: "all", "hashes"
	List string `json:"list,omitempty"`
}

// UHRPLookupService implements overlay.LookupService for UHRP content resolution.
type UHRPLookupService struct {
	engine *overlay.Engine
}

// NewUHRPLookupService creates a UHRP lookup service.
func NewUHRPLookupService(engine *overlay.Engine) *UHRPLookupService {
	return &UHRPLookupService{engine: engine}
}

// Lookup answers a UHRP query.
func (ls *UHRPLookupService) Lookup(queryRaw json.RawMessage) (*overlay.LookupAnswer, error) {
	var q UHRPLookupQuery
	if err := json.Unmarshal(queryRaw, &q); err != nil {
		return nil, fmt.Errorf("invalid UHRP query: %w", err)
	}

	outputs, err := ls.engine.GetOutputsByTopic(UHRPTopicName)
	if err != nil {
		return nil, err
	}

	if q.ContentHash != "" {
		// Find outputs matching the content hash
		hash := strings.ToLower(q.ContentHash)
		var matches []overlay.AdmittedOutput
		for _, out := range outputs {
			var entry UHRPEntry
			if err := json.Unmarshal(out.Metadata, &entry); err != nil {
				continue
			}
			if strings.ToLower(entry.ContentHash) == hash {
				matches = append(matches, out)
			}
		}
		return &overlay.LookupAnswer{
			Type:    "output-list",
			Outputs: matches,
		}, nil
	}

	if q.List == "all" {
		return &overlay.LookupAnswer{
			Type:    "output-list",
			Outputs: outputs,
		}, nil
	}

	if q.List == "hashes" {
		// Return unique hashes with counts
		hashCounts := make(map[string]int)
		for _, out := range outputs {
			var entry UHRPEntry
			if err := json.Unmarshal(out.Metadata, &entry); err != nil {
				continue
			}
			hashCounts[entry.ContentHash]++
		}
		return &overlay.LookupAnswer{
			Type:   "freeform",
			Result: hashCounts,
		}, nil
	}

	return nil, fmt.Errorf("UHRP query must specify content_hash or list")
}

// GetDocumentation returns a description of the UHRP lookup service.
func (ls *UHRPLookupService) GetDocumentation() string {
	return "UHRP Lookup (BRC-26): Resolve content by SHA-256 hash. Query by hash to find hosting locations, or list all advertised content."
}

// GetMetadata returns machine-readable metadata about the UHRP lookup service.
func (ls *UHRPLookupService) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":     26,
		"service": UHRPLookupServiceName,
		"queries": []string{"content_hash", "list"},
	}
}

// Ensure UHRPLookupService implements LookupService at compile time.
var _ overlay.LookupService = (*UHRPLookupService)(nil)
