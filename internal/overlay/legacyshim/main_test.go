package legacyshim_test

import (
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/netguard"
)

// TestMain guards http.DefaultClient as the node does at start-up, before any
// test runs, so the engine's propagation from a legacy submit (go-sdk's
// broadcast and lookup facilitators run on http.DefaultClient) is tested as
// it runs in production.
func TestMain(m *testing.M) {
	netguard.Install()
	os.Exit(m.Run())
}
