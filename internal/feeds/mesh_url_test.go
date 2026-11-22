package feeds

import (
	"encoding/json"
	"testing"
)

func TestHeartbeatMeshURLFollowsSource(t *testing.T) {
	pub, store, _ := testPublisher(t)
	sources := HeartbeatSources{
		HeightFn: func() uint32 { return 1 },
		PeersFn:  func() int { return 0 },
		TopicsFn: func() map[string]int { return nil },
	}
	pub.publishHeartbeat(300, sources)
	sources.MeshURLFn = func() string { return "wss://node.example/mesh" }
	pub.publishHeartbeat(300, sources)

	envs, err := store.QueryByTopic("mesh:heartbeat", 10)
	if err != nil || len(envs) != 2 {
		t.Fatalf("heartbeats: count=%d error=%v", len(envs), err)
	}
	withURL, withoutURL := 0, 0
	for _, env := range envs {
		var payload map[string]any
		if err := json.Unmarshal([]byte(env.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["mesh_url"] == "wss://node.example/mesh" {
			withURL++
		} else if _, present := payload["mesh_url"]; !present {
			withoutURL++
		}
	}
	if withURL != 1 || withoutURL != 1 {
		t.Fatalf("heartbeat mesh URL counts: with=%d without=%d", withURL, withoutURL)
	}
}
