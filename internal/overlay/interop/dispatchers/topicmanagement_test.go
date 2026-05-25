package dispatchers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/canonical"
	"github.com/BSVanon/Anvil/internal/overlay/interop"
)

func loadTopicManagementFile(t *testing.T) *interop.VectorFile {
	t.Helper()
	abs, err := filepath.Abs("../../../../docs/internal/conformance-vectors")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	files, err := interop.LoadAll(abs)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	for _, f := range files {
		if f.ID == "overlay.topicmanagement" {
			return f
		}
	}
	t.Fatal("overlay.topicmanagement file not found in pinned snapshot")
	return nil
}

func vectorByID(t *testing.T, file *interop.VectorFile, id string) interop.Vector {
	t.Helper()
	for _, v := range file.Vectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not found in %s", id, file.ID)
	return interop.Vector{}
}

// freshDispatcher returns a dispatcher backed by a canonical handler with the
// counts and readiness the conformance vectors expect. Production wiring
// passes BOTH a ready and a not-ready handler so vector .2 can PASS without
// flipping global state mid-run.
func freshDispatcher(ready bool) *TopicManagement {
	cfg := canonical.Config{
		NodeName:           "overlay-node",
		Network:            "main",
		Ready:              func() bool { return ready },
		TopicManagerCount:  func() int { return 2 },
		LookupServiceCount: func() int { return 2 },
	}
	return NewTopicManagement(canonical.New(cfg))
}

// productionDispatcher returns the dispatcher shape used by anvil-conformance:
// the default handler + scenario-specific fixtures for vectors that need
// non-default node state. Used by all vectors .1-.8 + .17/.18.
func productionDispatcher() *TopicManagement {
	readyCfg := canonical.Config{
		NodeName:           "overlay-node",
		Network:            "main",
		Ready:              func() bool { return true },
		TopicManagerCount:  func() int { return 2 },
		LookupServiceCount: func() int { return 2 },
	}
	notReadyCfg := readyCfg
	notReadyCfg.Ready = func() bool { return false }

	adminIdentityCfg := readyCfg
	adminIdentityCfg.NodeName = "overlay-test-node"
	adminIdentityCfg.AdminIdentityKey = "02a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	adminStatsCfg := readyCfg
	adminStatsCfg.NodeName = "overlay-test-node"
	adminStatsCfg.AdminBearerToken = "test-admin-token-abc123"
	adminStatsCfg.TopicManagerNames = func() []string { return []string{"tm_ship", "tm_slap"} }
	adminStatsCfg.LookupServiceNames = func() []string { return []string{"ls_ship", "ls_slap"} }

	return NewTopicManagement(canonical.New(readyCfg)).
		WithScenario(ScenarioNotReady, canonical.New(notReadyCfg)).
		WithScenario(ScenarioWithAdminIdentity, canonical.New(adminIdentityCfg)).
		WithScenario(ScenarioAdminStats, canonical.New(adminStatsCfg))
}

func TestTopicManagement_Vector1_HealthFullCheck(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.1")

	d := freshDispatcher(true)
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector3_LivenessProbe(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.3")

	d := freshDispatcher(false) // liveness is independent of readiness
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector4_ReadinessProbe(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.4")

	d := freshDispatcher(true)
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector2_NotReadyHealth(t *testing.T) {
	// With the production dispatcher (ready + notReady handlers attached),
	// vector .2 should route to the notReady handler and PASS: 503 +
	// live=true + ready=false + status=degraded.
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.2")

	d := productionDispatcher()
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector2_FallsBackToMainHandler(t *testing.T) {
	// Without a notReady handler attached, vector .2 routes through the
	// main handler. If that handler is ready (returns 200), the vector
	// FAILs (vector expects 503). This is the behavior Codex called out:
	// the dispatcher should produce a real result, not a silent SKIP.
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.2")

	d := freshDispatcher(true) // ready=true, no notReady handler
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s, want FAIL (ready=true cannot satisfy vector .2)", res.Status)
	}
}

func TestTopicManagement_RemainingVectorsPending(t *testing.T) {
	file := loadTopicManagementFile(t)
	d := productionDispatcher()

	pendingCount := 0
	for _, v := range file.Vectors {
		switch v.ID {
		case "overlay.topicmanagement.1",
			"overlay.topicmanagement.2",
			"overlay.topicmanagement.3",
			"overlay.topicmanagement.4",
			"overlay.topicmanagement.5",
			"overlay.topicmanagement.6",
			"overlay.topicmanagement.7",
			"overlay.topicmanagement.8",
			"overlay.topicmanagement.17",
			"overlay.topicmanagement.18":
			continue
		}
		res := d.Run(context.Background(), file, v)
		if res.Status != interop.StatusPending {
			t.Errorf("%s: status = %s, want PENDING", v.ID, res.Status)
		} else {
			pendingCount++
		}
	}
	// 18 total - 10 (handled) = 8 expected PENDING (Workstream D vectors).
	if pendingCount != 8 {
		t.Errorf("PENDING count = %d, want 8", pendingCount)
	}
}

func TestTopicManagement_Vector7_AdminStatsNoAuth(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.7")
	res := productionDispatcher().Run(context.Background(), file, v)
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector8_AdminStatsValidBearer(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.8")
	res := productionDispatcher().Run(context.Background(), file, v)
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector17_ArcIngestHappyPath(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.17")
	res := productionDispatcher().Run(context.Background(), file, v)
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector18_ArcIngestMissingTxid(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.18")
	res := productionDispatcher().Run(context.Background(), file, v)
	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector8_MissingAdminStatsScenario_FALL_THROUGH(t *testing.T) {
	// Without the admin-stats scenario attached, vector .8 falls back to
	// default (which doesn't have a Bearer token configured), so the request
	// gets 401 instead of 200. Vector expects 200, dispatcher should FAIL.
	// This is the safety net Codex b126d8fc asked us to preserve.
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.8")
	d := freshDispatcher(true) // no admin-stats scenario attached
	res := d.Run(context.Background(), file, v)
	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s, want FAIL (default scenario lacks admin bearer)", res.Status)
	}
}

func TestTopicManagement_Vector5_AdminConfigWithIdentity(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.5")

	d := productionDispatcher()
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector6_AdminConfigNoIdentity(t *testing.T) {
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.6")

	d := productionDispatcher()
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusPass {
		t.Fatalf("status = %s (msg=%s), want PASS", res.Status, res.Message)
	}
}

func TestTopicManagement_Vector5_MissingScenarioFallsBackAndFails(t *testing.T) {
	// If the admin-identity scenario isn't attached, vector .5 falls back to
	// default (no admin identity, nodeName=overlay-node). That handler returns
	// adminIdentityKey: null + nodeName: overlay-node — both mismatch vector .5's
	// expected values, so the dispatcher should FAIL honestly.
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.5")

	d := freshDispatcher(true) // ready=true, but no admin-identity scenario attached
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s, want FAIL (default scenario lacks admin identity)", res.Status)
	}
}

func TestTopicManagement_PerVectorWorkstream(t *testing.T) {
	// Codex review b126d8fc: Result.Workstream must reflect the vector's
	// owning workstream, not the file's umbrella label. The runner's
	// PendingByWorkstream relies on this field for honest backlog counts.
	file := loadTopicManagementFile(t)
	d := productionDispatcher()

	// .5-.8, .17, .18 are Workstream A; .9-.16 are Workstream D.
	cases := map[string]string{
		"overlay.topicmanagement.5":  "A",
		"overlay.topicmanagement.9":  "D",
		"overlay.topicmanagement.16": "D",
		"overlay.topicmanagement.17": "A",
	}
	for id, wantWs := range cases {
		v := vectorByID(t, file, id)
		res := d.Run(context.Background(), file, v)
		if res.Workstream != wantWs {
			t.Errorf("%s: Workstream = %q, want %q", id, res.Workstream, wantWs)
		}
	}
}

func TestTopicManagement_RealFailDetected(t *testing.T) {
	// Sanity: if the handler returns wrong data, the dispatcher should FAIL,
	// not silently PASS. Build a dispatcher whose Ready=false flips the
	// canonical response away from the vector's expected shape.
	file := loadTopicManagementFile(t)
	v := vectorByID(t, file, "overlay.topicmanagement.1")

	d := freshDispatcher(false) // /health will now return 503 + ready=false
	res := d.Run(context.Background(), file, v)

	if res.Status != interop.StatusFail {
		t.Fatalf("status = %s (msg=%s), want FAIL (handler returned 503 but vector expects 200)", res.Status, res.Message)
	}
}

func TestMatchSubset_OneOfHandling(t *testing.T) {
	want := map[string]any{
		"status_oneof": []any{"degraded", "error"},
	}
	got := map[string]any{"status": "degraded"}
	if msg := matchSubset(want, got, ""); msg != "" {
		t.Errorf("unexpected mismatch: %s", msg)
	}

	got2 := map[string]any{"status": "ok"}
	if msg := matchSubset(want, got2, ""); msg == "" {
		t.Error("expected mismatch for status=ok against oneof[degraded,error]")
	}
}

func TestMatchSubset_NestedObject(t *testing.T) {
	want := map[string]any{
		"service": map[string]any{
			"name":    "overlay-node",
			"network": "main",
		},
	}
	got := map[string]any{
		"service": map[string]any{
			"name":    "overlay-node",
			"network": "main",
			"extra":   "ignored", // extra keys in got are allowed
		},
	}
	if msg := matchSubset(want, got, ""); msg != "" {
		t.Errorf("unexpected mismatch: %s", msg)
	}

	got2 := map[string]any{
		"service": map[string]any{
			"name":    "overlay-node",
			"network": "test", // wrong value
		},
	}
	if msg := matchSubset(want, got2, ""); msg == "" {
		t.Error("expected mismatch for network=test against want main")
	}
}
