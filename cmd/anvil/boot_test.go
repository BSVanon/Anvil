package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestMain(m *testing.M) {
	if os.Getenv("ANVIL_TEST_RUN_MAIN") == "1" {
		os.Args = []string{os.Args[0], "-config", os.Getenv("ANVIL_TEST_CONFIG")}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNodeStartsAndStops(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a node subprocess")
	}
	node := newBootNode(t, "one", "")
	node.start(t)
	node.waitForReady(t)
	node.stop(t)
}

func TestSeededNodesReportMeshPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("starts node subprocesses")
	}
	a := newBootNode(t, "one", "")
	a.start(t)
	a.waitForReady(t)
	b := newBootNode(t, "two", "ws://"+a.meshListen)
	b.start(t)
	b.waitForReady(t)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if a.meshPeers() == 1 && b.meshPeers() == 1 {
			return
		}
		if a.exited() || b.exited() {
			t.Fatalf("node exited before mesh peering:\nA:\n%s\nB:\n%s", a.lastLines(), b.lastLines())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nodes did not report one mesh peer within 30 seconds:\nA:\n%s\nB:\n%s", a.lastLines(), b.lastLines())
}

type bootNode struct {
	meshListen string
	apiListen  string
	configPath string
	output     lockedBuffer
	cmd        *exec.Cmd
	done       chan struct{}
	mu         sync.Mutex
	exitErr    error
	stopped    bool
}

func newBootNode(t *testing.T, name, seed string) *bootNode {
	t.Helper()
	meshListen := freeLoopbackAddress(t)
	apiListen := freeLoopbackAddress(t)
	dataDir := filepath.Join(t.TempDir(), name)
	for _, subdir := range []string{"headers", "envelopes", "overlay", "wallet", "invoices", "proofs", "mesh"} {
		if err := os.MkdirAll(filepath.Join(dataDir, subdir), 0755); err != nil {
			t.Fatalf("create %s: %v", subdir, err)
		}
	}

	configBytes, err := os.ReadFile(filepath.Join("..", "..", "anvil.example.toml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	config := string(configBytes)
	config = replaceConfigValue(t, config, "node", "data_dir", fmt.Sprintf("%q", dataDir))
	config = replaceConfigValue(t, config, "node", "listen", fmt.Sprintf("%q", meshListen))
	config = replaceConfigValue(t, config, "node", "api_listen", fmt.Sprintf("%q", apiListen))
	config = replaceConfigValue(t, config, "arc", "enabled", "false")
	config = replaceConfigValue(t, config, "overlay", "enable_gasp_sync", "false")
	if seed != "" {
		config = replaceMeshSeeds(t, config, seed)
	}
	configPath := filepath.Join(t.TempDir(), name+".toml")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return &bootNode{meshListen: meshListen, apiListen: apiListen, configPath: configPath, done: make(chan struct{}), cmd: exec.Command(os.Args[0], "-test.run=^$"), exitErr: nil}
}

func (n *bootNode) start(t *testing.T) {
	t.Helper()
	n.cmd.Env = environmentWithout("ANVIL_TEST_RUN_MAIN", "ANVIL_TEST_CONFIG", "ANVIL_IDENTITY_WIF")
	n.cmd.Env = append(n.cmd.Env, "ANVIL_TEST_RUN_MAIN=1", "ANVIL_TEST_CONFIG="+n.configPath)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	n.cmd.Env = append(n.cmd.Env, "ANVIL_IDENTITY_WIF="+key.Wif())
	n.cmd.Stdout = &n.output
	n.cmd.Stderr = &n.output
	if err := n.cmd.Start(); err != nil {
		t.Fatalf("start node: %v", err)
	}
	go func() {
		err := n.cmd.Wait()
		n.mu.Lock()
		n.exitErr = err
		n.mu.Unlock()
		close(n.done)
	}()
	t.Cleanup(func() { n.stop(t) })
}

func environmentWithout(keys ...string) []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		keep := true
		for _, key := range keys {
			if strings.HasPrefix(entry, key+"=") {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (n *bootNode) waitForReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if n.statusOK() && strings.Contains(n.output.String(), "REST API listening") {
			return
		}
		if n.exited() {
			t.Fatalf("node exited before its REST API was ready:\n%s", n.lastLines())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("REST API did not become ready within 30 seconds:\n%s", n.lastLines())
}

func (n *bootNode) stop(t *testing.T) {
	t.Helper()
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return
	}
	n.stopped = true
	n.mu.Unlock()
	if !n.exited() {
		if err := n.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Errorf("signal node: %v\n%s", err, n.lastLines())
			return
		}
	}
	select {
	case <-n.done:
		n.mu.Lock()
		err := n.exitErr
		n.mu.Unlock()
		if err != nil {
			t.Errorf("node did not exit cleanly: %v\n%s", err, n.lastLines())
		}
	case <-time.After(15 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.done
		t.Errorf("node did not exit within 15 seconds:\n%s", n.lastLines())
	}
}

func (n *bootNode) statusOK() bool {
	resp, err := bootHTTPClient.Get("http://" + n.apiListen + "/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (n *bootNode) meshPeers() int {
	resp, err := bootHTTPClient.Get("http://" + n.apiListen + "/status")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	var status struct {
		Mesh struct {
			Peers int `json:"peers"`
		} `json:"mesh"`
	}
	if json.NewDecoder(resp.Body).Decode(&status) != nil {
		return -1
	}
	return status.Mesh.Peers
}

var bootHTTPClient = &http.Client{Timeout: time.Second}

func (n *bootNode) exited() bool {
	select {
	case <-n.done:
		return true
	default:
		return false
	}
}

func (n *bootNode) lastLines() string { return lastLines(n.output.String()) }

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return addr
}

func replaceConfigValue(t *testing.T, config, section, key, value string) string {
	t.Helper()
	lines := strings.Split(config, "\n")
	inSection := false
	for i, line := range lines {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = line == "["+section+"]"
			continue
		}
		if inSection && strings.HasPrefix(strings.TrimSpace(line), key+" =") {
			lines[i] = key + " = " + value
			return strings.Join(lines, "\n")
		}
	}
	t.Fatalf("missing [%s] %s", section, key)
	return ""
}

func replaceMeshSeeds(t *testing.T, config, seed string) string {
	t.Helper()
	lines := strings.Split(config, "\n")
	inMesh, inSeeds := false, false
	for i, line := range lines {
		if line == "[mesh]" {
			inMesh = true
			continue
		}
		if inMesh && strings.HasPrefix(strings.TrimSpace(line), "seeds = [") {
			lines[i] = "seeds = [" + fmt.Sprintf("%q", seed) + "]"
			inSeeds = true
			continue
		}
		if inSeeds {
			lines[i] = ""
			if strings.TrimSpace(line) == "]" {
				return strings.Join(lines, "\n")
			}
		}
	}
	t.Fatal("missing [mesh] seeds")
	return ""
}

func lastLines(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return strings.Join(lines, "\n")
}
