package legacyshim

import (
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
)

// TestSubmitBackgroundCap_IsTheCanonicalDeadline: the legacy submit's cap is
// the canonical /submit's deadline, and with netguard's bound on each
// propagation exchange a submit on either route ends within 45 s, inside a
// reverse proxy's 60 s default.
func TestSubmitBackgroundCap_IsTheCanonicalDeadline(t *testing.T) {
	if submitBackgroundCap != v3engine.DefaultSubmitTimeout {
		t.Errorf("submitBackgroundCap = %v, the canonical deadline is %v", submitBackgroundCap, v3engine.DefaultSubmitTimeout)
	}
	if worst := submitBackgroundCap + netguard.SubmitTimeout; worst > 45*time.Second {
		t.Errorf("a submit may take %v, over 45 s", worst)
	}
}
