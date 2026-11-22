package main

import (
	"os"
	"strings"
	"testing"
)

func TestPrivateHomePolicyIsInstalledBeforeMeshStarts(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	reconcile := strings.Index(text, "buildStartupMessagingPolicy(cfg")
	install := strings.Index(text, "applyGossipMessagingPolicy(gossipMgr")
	startMesh := strings.Index(text, "startMeshNetworking(context.Background()")
	if reconcile < 0 || install < 0 || startMesh < 0 {
		t.Fatal("private-home or mesh startup call is missing")
	}
	if reconcile > install || install > startMesh {
		t.Fatal("private-home policy is installed after mesh traffic can begin")
	}

	meshSource, err := os.ReadFile("mesh_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	meshText := string(meshSource)
	if !strings.Contains(meshText, "ConnectSeedWithReconnect(ctx") ||
		!strings.Contains(meshText, "startMeshListener(cfg, manager)") {
		t.Fatal("mesh startup no longer owns both seed and listener startup")
	}
}
