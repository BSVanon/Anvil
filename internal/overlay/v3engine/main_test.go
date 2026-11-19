package v3engine

import (
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/netguard"
)

// TestMain guards http.DefaultClient as the node does at start-up, before any
// test runs, so the engine's propagation path (go-overlay-services builds its
// lookup resolver on http.DefaultClient) is tested as it runs in production.
func TestMain(m *testing.M) {
	netguard.Install()
	os.Exit(m.Run())
}
