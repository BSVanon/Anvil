package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type upgradeHealthRoundTripper func(*http.Request) (*http.Response, error)

func (f upgradeHealthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type recordedUpgradeControl struct {
	events []string
}

func (r *recordedUpgradeControl) deps(probe func(string) error) upgradeHealthDeps {
	now := time.Unix(1_700_000_000, 0)
	return upgradeHealthDeps{
		probe: probe,
		service: upgradeServiceControl{
			start: func(unit string) error {
				r.events = append(r.events, "start "+unit)
				return nil
			},
			stop: func(unit string) error {
				r.events = append(r.events, "stop "+unit)
				return nil
			},
		},
		clock: upgradeClock{
			now: func() time.Time { return now },
			sleep: func(delay time.Duration) {
				now = now.Add(delay)
			},
		},
	}
}

func writeUpgradeBinaryPair(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	destination := filepath.Join(dir, "anvil")
	backup := destination + ".bak"
	if err := os.WriteFile(destination, []byte("new binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}
	return destination, backup
}

func TestRestartedServicesHealthyKeepsUpgrade(t *testing.T) {
	control := &recordedUpgradeControl{}
	probes := make(map[string]int)
	deps := control.deps(func(url string) error {
		probes[url]++
		return nil
	})
	plan := upgradeRestartPlan{
		services:  []string{"anvil-a", "anvil-b"},
		endpoints: map[string]string{"anvil-a": "http://a/status", "anvil-b": "http://b/status"},
		timeout:   5 * time.Second,
	}

	if err := restartServicesWithHealth(plan, deps); err != nil {
		t.Fatalf("healthy restart failed: %v", err)
	}
	wantEvents := []string{"start anvil-a", "start anvil-b"}
	if !reflect.DeepEqual(control.events, wantEvents) {
		t.Fatalf("service actions = %v, want %v", control.events, wantEvents)
	}
	if probes["http://a/status"] != 1 || probes["http://b/status"] != 1 {
		t.Fatalf("probe counts = %v, want one per service", probes)
	}
}

func TestUnresponsiveUpgradedServiceRestoresPreviousBinary(t *testing.T) {
	destination, backup := writeUpgradeBinaryPair(t)
	marker := filepath.Join(t.TempDir(), "migration-started.log")
	if err := os.WriteFile(marker, []byte("unchanged\n"), 0640); err != nil {
		t.Fatal(err)
	}
	control := &recordedUpgradeControl{}
	deps := control.deps(func(url string) error {
		binary, err := os.ReadFile(destination)
		if err != nil {
			return err
		}
		if string(binary) == "new binary" && strings.Contains(url, "b/status") {
			return errors.New("API never answered")
		}
		return nil
	})
	plan := upgradeRestartPlan{
		services:        []string{"anvil-a", "anvil-b"},
		endpoints:       map[string]string{"anvil-a": "http://a/status", "anvil-b": "http://b/status"},
		markerPaths:     map[string]string{"anvil-a": marker, "anvil-b": marker},
		destination:     destination,
		backup:          backup,
		backupAvailable: true,
		timeout:         2 * time.Second,
	}

	err := restartServicesWithHealth(plan, deps)
	if err == nil || !strings.Contains(err.Error(), "upgrade rolled back") ||
		!strings.Contains(err.Error(), "anvil-b") || !strings.Contains(err.Error(), "within 2s") {
		t.Fatalf("rollback report = %v", err)
	}
	binary, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(binary) != "old binary" {
		t.Fatalf("installed binary = %q, want previous binary", binary)
	}
	wantEvents := []string{
		"start anvil-a", "start anvil-b",
		"stop anvil-a", "stop anvil-b",
		"start anvil-a", "start anvil-b",
	}
	if !reflect.DeepEqual(control.events, wantEvents) {
		t.Fatalf("service actions = %v, want %v", control.events, wantEvents)
	}
}

func TestDaemonMigrationPreventsAutomaticHealthRollback(t *testing.T) {
	destination, backup := writeUpgradeBinaryPair(t)
	dataDir := t.TempDir()
	marker := filepath.Join(dataDir, "migration-started.log")
	if err := os.WriteFile(marker, []byte("before\n"), 0640); err != nil {
		t.Fatal(err)
	}
	control := &recordedUpgradeControl{}
	deps := control.deps(func(string) error { return errors.New("API unavailable") })
	deps.service.start = func(unit string) error {
		control.events = append(control.events, "start "+unit)
		f, err := os.OpenFile(marker, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := f.WriteString("2026-11-21T12:00:00Z\t3.5.2\tmessagebox-v1-to-v2\n")
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	plan := upgradeRestartPlan{
		services:        []string{"anvil-a"},
		endpoints:       map[string]string{"anvil-a": "http://a/status"},
		markerPaths:     map[string]string{"anvil-a": marker},
		destination:     destination,
		backup:          backup,
		backupAvailable: true,
		timeout:         time.Second,
	}

	err := restartServicesWithHealth(plan, deps)
	if err == nil || !strings.Contains(err.Error(), "a restarted daemon began a data migration") ||
		!strings.Contains(err.Error(), "messagebox-v1-to-v2") || !strings.Contains(err.Error(), "upgrade health check failed") {
		t.Fatalf("migration safety report = %v", err)
	}
	binary, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(binary) != "new binary" {
		t.Fatalf("installed binary = %q, migration must keep new binary", binary)
	}
	if !reflect.DeepEqual(control.events, []string{"start anvil-a"}) {
		t.Fatalf("service actions = %v", control.events)
	}
}

func TestUnreadableMigrationMarkerStartsServicesWithoutAutomaticRollback(t *testing.T) {
	destination, backup := writeUpgradeBinaryPair(t)
	control := &recordedUpgradeControl{}
	deps := control.deps(func(string) error { return errors.New("API unavailable") })
	plan := upgradeRestartPlan{
		services:        []string{"anvil-a"},
		endpoints:       map[string]string{"anvil-a": "http://a/status"},
		markerPaths:     map[string]string{"anvil-a": t.TempDir()},
		destination:     destination,
		backup:          backup,
		backupAvailable: true,
		timeout:         time.Second,
	}

	err := restartServicesWithHealth(plan, deps)
	if err == nil || !strings.Contains(err.Error(), "migration marker could not be read before services started") ||
		!strings.Contains(err.Error(), "startup migration cannot be ruled out") {
		t.Fatalf("marker safety report = %v", err)
	}
	binary, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(binary) != "new binary" {
		t.Fatalf("installed binary = %q, unreadable marker must keep new binary", binary)
	}
	if !reflect.DeepEqual(control.events, []string{"start anvil-a"}) {
		t.Fatalf("service actions = %v", control.events)
	}
}

func TestPreviousBinaryHealthFailureRequestsManualIntervention(t *testing.T) {
	destination, backup := writeUpgradeBinaryPair(t)
	control := &recordedUpgradeControl{}
	deps := control.deps(func(url string) error {
		if strings.Contains(url, "b/status") {
			return errors.New("API unavailable")
		}
		return nil
	})
	plan := upgradeRestartPlan{
		services:        []string{"anvil-a", "anvil-b"},
		endpoints:       map[string]string{"anvil-a": "http://a/status", "anvil-b": "http://b/status"},
		destination:     destination,
		backup:          backup,
		backupAvailable: true,
		timeout:         time.Second,
	}

	err := restartServicesWithHealth(plan, deps)
	if err == nil {
		t.Fatal("expected rollback health failure")
	}
	if !strings.Contains(err.Error(), "previous binary was restored") ||
		!strings.Contains(err.Error(), "manual intervention required for units: anvil-b") {
		t.Fatalf("manual-intervention report = %v", err)
	}
	binary, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(binary) != "old binary" {
		t.Fatalf("installed binary = %q, want previous binary", binary)
	}
}

func TestMigrationPreventsAutomaticHealthRollback(t *testing.T) {
	destination, backup := writeUpgradeBinaryPair(t)
	control := &recordedUpgradeControl{}
	deps := control.deps(func(string) error { return errors.New("API unavailable") })
	plan := upgradeRestartPlan{
		services:        []string{"anvil-a"},
		endpoints:       map[string]string{"anvil-a": "http://a/status"},
		destination:     destination,
		backup:          backup,
		backupAvailable: true,
		migrationRan:    true,
		timeout:         time.Second,
	}

	err := restartServicesWithHealth(plan, deps)
	if err == nil || !strings.Contains(err.Error(), "automatic rollback was not attempted because a data migration ran") {
		t.Fatalf("migration safety report = %v", err)
	}
	if !strings.Contains(err.Error(), "manual intervention required for units: anvil-a") {
		t.Fatalf("migration report does not name failed unit: %v", err)
	}
	binary, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(binary) != "new binary" {
		t.Fatalf("installed binary = %q, migration must keep new binary", binary)
	}
	wantEvents := []string{"start anvil-a"}
	if !reflect.DeepEqual(control.events, wantEvents) {
		t.Fatalf("service actions = %v, want %v", control.events, wantEvents)
	}
}

func TestServiceNotPreviouslyRunningRemainsUntouched(t *testing.T) {
	control := &recordedUpgradeControl{}
	var probed []string
	deps := control.deps(func(url string) error {
		probed = append(probed, url)
		return nil
	})
	plan := upgradeRestartPlan{
		services: []string{"anvil-a"},
		endpoints: map[string]string{
			"anvil-a": "http://a/status",
			"anvil-b": "http://b/status",
		},
		timeout: time.Second,
	}

	if err := restartServicesWithHealth(plan, deps); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(control.events, []string{"start anvil-a"}) {
		t.Fatalf("service actions = %v, inactive service was touched", control.events)
	}
	if !reflect.DeepEqual(probed, []string{"http://a/status"}) {
		t.Fatalf("probed endpoints = %v, inactive service was checked", probed)
	}
}

func TestServiceHealthEndpointsUseUnitConfigAndSkipUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node-a.toml")
	dataDir := filepath.Join(dir, "data-a")
	if err := os.WriteFile(configPath, []byte("[node]\napi_listen = \"0.0.0.0:9444\"\ndata_dir = \""+dataDir+"\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	unitA := "[Service]\nExecStart=/opt/anvil/anvil -config " + configPath + "\n"
	unitB := "[Service]\nExecStart=/opt/anvil/anvil -config " + filepath.Join(dir, "missing.toml") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "anvil-a.service"), []byte(unitA), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anvil-b.service"), []byte(unitB), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, markers, failures := serviceHealthEndpoints(dir, []string{"anvil-a", "anvil-b"})
	if endpoints["anvil-a"] != "http://127.0.0.1:9444/status" {
		t.Fatalf("anvil-a endpoint = %q", endpoints["anvil-a"])
	}
	if _, ok := endpoints["anvil-b"]; ok {
		t.Fatal("unreadable config should not produce a health endpoint")
	}
	if markers["anvil-a"] != filepath.Join(dataDir, "migration-started.log") {
		t.Fatalf("anvil-a marker = %q", markers["anvil-a"])
	}
	if failures["anvil-b"] == nil {
		t.Fatal("unreadable config should produce a warning reason")
	}
}

func TestHealthProbeRequiresStatusOK(t *testing.T) {
	var method, path string
	client := &http.Client{Transport: upgradeHealthRoundTripper(func(req *http.Request) (*http.Response, error) {
		method = req.Method
		path = req.URL.Path
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Body:       io.NopCloser(strings.NewReader("starting")),
			Header:     make(http.Header),
		}, nil
	})}

	err := probeUpgradeStatusWithClient(client, "http://127.0.0.1:9444/status")
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("non-200 probe result = %v", err)
	}
	if method != http.MethodGet || path != "/status" {
		t.Fatalf("probe request = %s %s, want GET /status", method, path)
	}
}
