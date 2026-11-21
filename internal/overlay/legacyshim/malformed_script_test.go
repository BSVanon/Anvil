package legacyshim_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

// PreVerify is shared code; see v3engine/malformed_script_test.go for the
// input shape and mechanism.
// (internal/overlay/routeguard/verify.go's Ticket.PreVerify, called from both
// /submit and /overlay/submit), so this pins the same refusal for the legacy
// route: refused promptly, with the coded 400, in the legacy {"error",
// "code"} envelope, and with no meaningful heap growth.

// These bounds match v3engine/malformed_script_test.go's exactly: the same
// shape through the same shared PreVerify, so the same reasoning applies.
const (
	malformedScriptBodyBytes      = 300_000
	malformedScriptHeapBound      = 8 << 20
	malformedScriptWallClockBound = 2 * time.Second
)

func TestLegacySubmit_RefusesMalformedUnlockingScript(t *testing.T) {
	for _, op := range []overlaytest.SigOpcode{
		overlaytest.CheckSig, overlaytest.CheckSigVerify,
		overlaytest.CheckMultiSig, overlaytest.CheckMultiSigVerify,
	} {
		t.Run(op.String(), func(t *testing.T) {
			g := routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, 500*time.Millisecond)
			url := guardedShimServer(t, newWiredShim(t), g)
			beef := overlaytest.MalformedReparseBEEF(t, malformedScriptBodyBytes, 1, op)

			var code int
			var raw string
			start := time.Now()
			peak, base := hostiletest.HeapPeak(func() {
				code, raw = submitUHRP(t, url, beef)
			})
			took := time.Since(start)
			t.Logf("%s: %d bytes refused in %v, heap peak %.1f MiB over %.1f MiB base",
				op, len(beef), took, float64(peak)/(1<<20), float64(base)/(1<<20))

			if code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d %s, want 400", op, code, raw)
			}
			if !strings.Contains(raw, `"code":"`+routeguard.MalformedScriptCode+`"`) || !strings.Contains(raw, `"error":`) {
				t.Fatalf("%s: body %s, want code %s in the legacy envelope", op, raw, routeguard.MalformedScriptCode)
			}
			if took > malformedScriptWallClockBound {
				t.Errorf("%s: refused after %v, want under %v (the interpreter must never run)", op, took, malformedScriptWallClockBound)
			}
			if peak > malformedScriptHeapBound {
				t.Errorf("%s: heap peak %d bytes over base, want under %d (the locking script must never be reparsed)",
					op, peak, malformedScriptHeapBound)
			}
			assertIdle(t, g)
		})
	}
}
