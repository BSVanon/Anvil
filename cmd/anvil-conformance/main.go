// Command anvil-conformance runs Anvil's overlay conformance vector suite
// against the pinned snapshot under docs/internal/conformance-vectors/ and
// prints a human-readable report.
//
// During Phase 0a no dispatchers are registered, so every active vector is
// reported PENDING with its owning workstream. As workstreams land, real
// dispatchers register and the report converts to PASS/FAIL/SKIP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BSVanon/Anvil/internal/overlay/canonical"
	"github.com/BSVanon/Anvil/internal/overlay/interop"
	"github.com/BSVanon/Anvil/internal/overlay/interop/dispatchers"
)

func main() {
	var (
		vectorDir = flag.String("vectors", "docs/internal/conformance-vectors", "path to the pinned conformance-vectors directory")
	)
	flag.Parse()

	abs, err := filepath.Abs(*vectorDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve vector dir:", err)
		os.Exit(2)
	}
	files, err := interop.LoadAll(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load vectors:", err)
		os.Exit(2)
	}

	reg := interop.NewRegistry()

	// Workstream A — canonical health + admin/config surface. Fixture config
	// matches the conformance vectors' expectations (service.name="overlay-node",
	// network="main", counts=2). Three scenarios so vectors .2 and .5 route
	// to the right node-state fixture:
	//   - default       : ready, no admin identity, nodeName=overlay-node
	//   - not-ready     : ready=false (vector .2 — health degraded)
	//   - admin-identity: admin key set, nodeName=overlay-test-node (vector .5)
	// Production Anvil mounts canonical.Register against the live mux with
	// real engine counts instead.
	baseCfg := canonical.Config{
		NodeName:           "overlay-node",
		Network:            "main",
		Ready:              func() bool { return true },
		TopicManagerCount:  func() int { return 2 },
		LookupServiceCount: func() int { return 2 },
	}
	notReadyCfg := baseCfg
	notReadyCfg.Ready = func() bool { return false }

	adminCfg := baseCfg
	adminCfg.NodeName = "overlay-test-node"
	adminCfg.AdminIdentityKey = "02a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	adminStatsCfg := baseCfg
	adminStatsCfg.NodeName = "overlay-test-node"
	adminStatsCfg.AdminBearerToken = "test-admin-token-abc123"
	adminStatsCfg.TopicManagerNames = func() []string { return []string{"tm_ship", "tm_slap"} }
	adminStatsCfg.LookupServiceNames = func() []string { return []string{"ls_ship", "ls_slap"} }

	tmDispatcher := dispatchers.NewTopicManagement(canonical.New(baseCfg)).
		WithScenario(dispatchers.ScenarioNotReady, canonical.New(notReadyCfg)).
		WithScenario(dispatchers.ScenarioWithAdminIdentity, canonical.New(adminCfg)).
		WithScenario(dispatchers.ScenarioAdminStats, canonical.New(adminStatsCfg))
	if err := reg.Register(tmDispatcher); err != nil {
		fmt.Fprintln(os.Stderr, "register topicmanagement:", err)
		os.Exit(2)
	}

	// Workstream A — BRC-31 auth handshake (Pass 1: schema + missing-header
	// vectors). The canonical handler at /.well-known/auth is the same handler
	// the topicmanagement dispatcher already hosts; brc31_handshake just
	// reuses it. Crypto vectors land in Pass 2.
	brc31 := dispatchers.NewBRC31Handshake(canonical.New(baseCfg))
	if err := reg.Register(brc31); err != nil {
		fmt.Fprintln(os.Stderr, "register brc31-handshake:", err)
		os.Exit(2)
	}

	// Workstream B — overlay.submit. Default scenario has no KnownTopics
	// filter; "known-topics" scenario enables it for vector .7 (unknown
	// topic manager → 400). Happy-path vectors require per-vector fixture
	// scenarios; the dispatcher's RegisterHappyPathScenariosFromVectors
	// builds them from each vector's expected.body (Codex review ba3e80:
	// CLI owns the fixture wiring so miswiring is observable).
	submitDefault := canonical.New(canonical.Config{})
	submitKnown := canonical.New(canonical.Config{
		KnownTopics: func() []string { return []string{"tm_ship", "tm_slap"} },
	})
	submitDispatcher := dispatchers.NewOverlaySubmit(submitDefault).
		WithScenario(dispatchers.ScenarioSubmitKnown, submitKnown)

	// Register per-vector happy-path fixtures. Look up the loaded submit
	// vector file; pass it to the registration helper.
	for _, f := range files {
		if f.ID == "overlay.submit" {
			if err := submitDispatcher.RegisterHappyPathScenariosFromVectors(f); err != nil {
				fmt.Fprintln(os.Stderr, "register overlay.submit happy-path scenarios:", err)
				os.Exit(2)
			}
			break
		}
	}

	if err := reg.Register(submitDispatcher); err != nil {
		fmt.Fprintln(os.Stderr, "register overlay.submit:", err)
		os.Exit(2)
	}

	// TODO: register more dispatchers as workstreams land:
	//   - Workstream C: overlay.lookup
	//   - Workstream D: SHIP/SLAP (overlay.topicmanagement bans/evictions)
	//   - Workstream E: sync.gasprotocol

	report := interop.Run(context.Background(), files, reg)
	interop.FormatSummary(os.Stdout, files, report)

	if report.Fail > 0 || report.Error > 0 {
		os.Exit(1)
	}
}
