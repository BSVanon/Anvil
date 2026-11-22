package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/migrationmarker"
)

const upgradeHealthPollInterval = 2 * time.Second

type upgradeServiceControl struct {
	start func(string) error
	stop  func(string) error
}

type upgradeClock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

type upgradeHealthDeps struct {
	probe   func(string) error
	service upgradeServiceControl
	clock   upgradeClock
}

type upgradeRestartPlan struct {
	services        []string
	endpoints       map[string]string
	markerPaths     map[string]string
	destination     string
	backup          string
	backupAvailable bool
	migrationRan    bool
	timeout         time.Duration
}

type serviceHealthFailure struct {
	unit   string
	reason string
}

type migrationMarkerChange struct {
	unit  string
	lines []string
	err   error
}

func productionUpgradeHealthDeps() upgradeHealthDeps {
	return upgradeHealthDeps{
		probe: probeUpgradeStatus,
		service: upgradeServiceControl{
			start: func(unit string) error { return exec.Command("systemctl", "start", unit).Run() },
			stop:  func(unit string) error { return exec.Command("systemctl", "stop", unit).Run() },
		},
		clock: upgradeClock{now: time.Now, sleep: time.Sleep},
	}
}

// serviceHealthEndpoints resolves each restarted unit's local /status endpoint
// and migration marker from one config load. A missing or unreadable config is
// returned as a per-unit error so the caller can warn and skip its health check.
func serviceHealthEndpoints(systemdDir string, services []string) (map[string]string, map[string]string, map[string]error) {
	paths := extractServiceConfigs(systemdDir, services)
	endpoints := make(map[string]string, len(paths))
	markers := make(map[string]string, len(paths))
	failures := make(map[string]error)
	for _, unit := range services {
		path, ok := paths[unit]
		if !ok {
			failures[unit] = fmt.Errorf("config path not found in unit")
			continue
		}
		cfg, err := config.Load(path)
		if err != nil {
			failures[unit] = fmt.Errorf("read %s: %w", path, err)
			continue
		}
		endpoints[unit] = fmt.Sprintf("http://127.0.0.1%s/status", normalizePort(cfg.Node.APIListen))
		markers[unit] = filepath.Join(cfg.Node.DataDir, migrationmarker.FileName)
	}
	return endpoints, markers, failures
}

func probeUpgradeStatus(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	return probeUpgradeStatusWithClient(client, url)
}

func probeUpgradeStatusWithClient(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	return nil
}

// restartServicesWithHealth starts only the units supplied in the plan and
// requires every configured endpoint to answer before accepting the upgrade.
// Any health failure restores the backup unless a data migration has run, a
// restarted daemon appended to its migration marker, or the pre-start marker
// snapshot could not be read.
func restartServicesWithHealth(plan upgradeRestartPlan, deps upgradeHealthDeps) error {
	markerSnapshots, markerSnapshotErr := snapshotMigrationMarkers(plan.services, plan.markerPaths)
	failures := startAndCheckUpgradeServices(plan.services, plan.endpoints, plan.timeout, deps)
	if len(failures) == 0 {
		return nil
	}

	failedUnits := healthFailureUnits(failures)
	failureDetail := formatHealthFailures(failures)
	if markerSnapshotErr != nil {
		return fmt.Errorf("upgrade health check failed: %s\n"+
			"automatic rollback was not attempted because a migration marker could not be read before services started, so a startup migration cannot be ruled out: %v\n"+
			"manual intervention required for units: %s\n"+
			"inspect logs: sudo journalctl %s\n"+
			"after correcting the failure, restart: sudo systemctl restart %s",
			failureDetail, markerSnapshotErr, strings.Join(failedUnits, ", "), journalUnitArgs(failedUnits), strings.Join(failedUnits, " "))
	}
	markerChanges := changedMigrationMarkers(plan.services, plan.markerPaths, markerSnapshots)
	if plan.migrationRan || len(markerChanges) > 0 {
		reason := "a data migration ran during this upgrade"
		markerDetail := ""
		if len(markerChanges) > 0 {
			reason = "a restarted daemon began a data migration"
			markerDetail = "\nnew migration marker lines:\n" + formatMigrationMarkerChanges(markerChanges)
		}
		return fmt.Errorf("upgrade health check failed: %s\n"+
			"automatic rollback was not attempted because %s; an older binary may not read the migrated data%s\n"+
			"manual intervention required for units: %s\n"+
			"inspect logs: sudo journalctl %s\n"+
			"after correcting the failure, restart: sudo systemctl restart %s",
			failureDetail, reason, markerDetail, strings.Join(failedUnits, ", "), journalUnitArgs(failedUnits), strings.Join(failedUnits, " "))
	}
	if !plan.backupAvailable {
		return fmt.Errorf("upgrade health check failed: %s\n"+
			"automatic rollback was not possible because no previous binary backup is available\n"+
			"manual intervention required for units: %s",
			failureDetail, strings.Join(failedUnits, ", "))
	}

	stopFailures := make(map[string]error)
	for _, unit := range plan.services {
		if err := deps.service.stop(unit); err != nil {
			stopFailures[unit] = err
		}
	}
	if err := os.Rename(plan.backup, plan.destination); err != nil {
		return fmt.Errorf("upgrade health check failed: %s\n"+
			"automatic rollback could not restore the previous binary: %v\n"+
			"manual intervention required for units: %s",
			failureDetail, err, strings.Join(failedUnits, ", "))
	}

	rollbackFailures := startAndCheckUpgradeServices(plan.services, plan.endpoints, plan.timeout, deps)
	for _, unit := range plan.services {
		if err, ok := stopFailures[unit]; ok {
			rollbackFailures = append(rollbackFailures, serviceHealthFailure{
				unit: unit, reason: fmt.Sprintf("could not stop upgraded service before rollback: %v", err),
			})
		}
	}
	if len(rollbackFailures) > 0 {
		rollbackUnits := healthFailureUnits(rollbackFailures)
		return fmt.Errorf("upgrade rolled back because health checks failed: %s\n"+
			"the previous binary was restored, but it also failed health checks: %s\n"+
			"manual intervention required for units: %s\n"+
			"inspect logs: sudo journalctl %s",
			failureDetail, formatHealthFailures(rollbackFailures), strings.Join(rollbackUnits, ", "), journalUnitArgs(rollbackUnits))
	}

	return fmt.Errorf("upgrade rolled back because health checks failed: %s\n"+
		"the previous binary was restored and the restarted services are healthy",
		failureDetail)
}

func snapshotMigrationMarkers(services []string, paths map[string]string) (map[string][]byte, error) {
	snapshots := make(map[string][]byte, len(paths))
	for _, unit := range services {
		path, ok := paths[unit]
		if !ok {
			continue
		}
		raw, err := readMigrationMarker(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot migration marker for %s: %w", unit, err)
		}
		snapshots[unit] = raw
	}
	return snapshots, nil
}

func changedMigrationMarkers(services []string, paths map[string]string, before map[string][]byte) []migrationMarkerChange {
	var changes []migrationMarkerChange
	for _, unit := range services {
		path, ok := paths[unit]
		if !ok {
			continue
		}
		after, err := readMigrationMarker(path)
		if err != nil {
			changes = append(changes, migrationMarkerChange{unit: unit, err: err})
			continue
		}
		if bytes.Equal(before[unit], after) {
			continue
		}
		delta := after
		if bytes.HasPrefix(after, before[unit]) {
			delta = after[len(before[unit]):]
		}
		lines := strings.Split(strings.TrimSpace(string(delta)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines[0] = "(marker was removed or emptied)"
		}
		changes = append(changes, migrationMarkerChange{unit: unit, lines: lines})
	}
	return changes
}

func readMigrationMarker(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return raw, err
}

func formatMigrationMarkerChanges(changes []migrationMarkerChange) string {
	var lines []string
	for _, change := range changes {
		if change.err != nil {
			lines = append(lines, fmt.Sprintf("  %s: marker could not be read after restart: %v", change.unit, change.err))
			continue
		}
		for _, line := range change.lines {
			lines = append(lines, fmt.Sprintf("  %s: %s", change.unit, line))
		}
	}
	return strings.Join(lines, "\n")
}

func startAndCheckUpgradeServices(services []string, endpoints map[string]string, timeout time.Duration, deps upgradeHealthDeps) []serviceHealthFailure {
	startFailures := make(map[string]error)
	for _, unit := range services {
		if err := deps.service.start(unit); err != nil {
			startFailures[unit] = err
		}
	}

	probeFailures := waitForUpgradeHealth(services, endpoints, timeout, deps.probe, deps.clock)
	failures := make([]serviceHealthFailure, 0, len(probeFailures)+len(startFailures))
	for _, unit := range services {
		if err, failed := probeFailures[unit]; failed {
			reason := err.Error()
			if startErr, startFailed := startFailures[unit]; startFailed {
				reason = fmt.Sprintf("systemctl start failed: %v; %s", startErr, reason)
			}
			failures = append(failures, serviceHealthFailure{unit: unit, reason: reason})
			continue
		}
		if _, checked := endpoints[unit]; checked {
			continue
		}
		if err, failed := startFailures[unit]; failed {
			failures = append(failures, serviceHealthFailure{unit: unit, reason: fmt.Sprintf("systemctl start failed: %v", err)})
		}
	}
	return failures
}

func waitForUpgradeHealth(services []string, endpoints map[string]string, timeout time.Duration, probe func(string) error, clock upgradeClock) map[string]error {
	pending := make(map[string]bool, len(endpoints))
	lastFailure := make(map[string]error, len(endpoints))
	for _, unit := range services {
		if _, ok := endpoints[unit]; ok {
			pending[unit] = true
		}
	}
	deadline := clock.now().Add(timeout)
	for len(pending) > 0 {
		for _, unit := range services {
			if !pending[unit] {
				continue
			}
			if err := probe(endpoints[unit]); err != nil {
				lastFailure[unit] = err
			} else {
				delete(pending, unit)
				delete(lastFailure, unit)
			}
		}
		if len(pending) == 0 || !clock.now().Before(deadline) {
			break
		}
		delay := upgradeHealthPollInterval
		if remaining := deadline.Sub(clock.now()); remaining < delay {
			delay = remaining
		}
		clock.sleep(delay)
	}
	for unit := range pending {
		lastFailure[unit] = fmt.Errorf("did not answer with HTTP 200 within %v: %w", timeout, lastFailure[unit])
	}
	return lastFailure
}

func formatHealthFailures(failures []serviceHealthFailure) string {
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		parts = append(parts, fmt.Sprintf("%s (%s)", failure.unit, failure.reason))
	}
	return strings.Join(parts, "; ")
}

func healthFailureUnits(failures []serviceHealthFailure) []string {
	seen := make(map[string]bool)
	units := make([]string, 0, len(failures))
	for _, failure := range failures {
		if !seen[failure.unit] {
			seen[failure.unit] = true
			units = append(units, failure.unit)
		}
	}
	return units
}

func journalUnitArgs(units []string) string {
	parts := make([]string, 0, len(units)*2)
	for _, unit := range units {
		parts = append(parts, "-u", unit)
	}
	return strings.Join(parts, " ")
}
