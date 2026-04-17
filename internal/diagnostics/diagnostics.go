// Package diagnostics provides operator-facing probes for detecting and
// recovering from the common failure modes that have bitten node operators:
//
//   - Orphan anvil processes (running but not tracked by systemd) that hold
//     LevelDB LOCKs on data directories, silently preventing the real
//     systemd-managed service from ever starting. Manifested as
//     "resource temporarily unavailable" on startup with a 200k+ systemd
//     restart counter.
//
//   - Crash-looping systemd units whose restart counter is growing without
//     bound, invisible because the orphan above is still answering on the
//     service's port.
//
//   - Header stores stuck on a reorg-incompatible tip, refusing to sync
//     further blocks with "prev hash mismatch" errors. Manifested as a
//     growing sync_lag_secs on the node's /mesh/status.
//
//   - Running process version != binary on disk (shared-binary upgrade
//     where only one of the services got restarted).
//
// All probes are read-only and safe to call from doctor. Remediation is
// explicit — the caller decides whether to execute the fix.
package diagnostics

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// AnvilBinaryPath is the canonical path to the installed binary. Processes
// executing from this path are considered "anvil processes" for orphan and
// service-version purposes. Kept as a var so tests can override it.
var AnvilBinaryPath = "/opt/anvil/anvil"

// AnvilProcess describes a running anvil process found on the host.
type AnvilProcess struct {
	PID        int    // process id
	CmdLine    string // full command line (null-separated args joined with space)
	ConfigPath string // parsed from `-config <path>` in the command line, if present
}

// ServiceState captures the systemd view of an anvil-*.service unit.
type ServiceState struct {
	Name        string // e.g. "anvil-a"
	ActiveState string // "active" | "activating" | "inactive" | "failed" | "unknown"
	SubState    string // "running" | "auto-restart" | "dead" | etc.
	NRestarts   int    // systemd's Restart counter
	MainPID     int    // 0 if no active main process
}

// LockHolder is a process that has an advisory file lock on a LevelDB LOCK
// file within a data directory.
type LockHolder struct {
	LockFile string // absolute path to the LOCK file
	PID      int    // pid holding the lock
	CmdLine  string // cmdline of that pid (for operator context)
}

// VersionMismatch describes a running process whose embedded version differs
// from the binary currently on disk at AnvilBinaryPath.
type VersionMismatch struct {
	Service    string // systemd unit name this process belongs to (empty for orphan)
	PID        int
	RunningVer string // version reported by the process's /status HTTP endpoint
	OnDiskVer  string // version embedded in the binary at AnvilBinaryPath
}

// EnumerateAnvilProcesses walks /proc and returns every process whose argv[0]
// resolves to AnvilBinaryPath. Includes systemd-managed services AND any
// orphan processes that systemd isn't tracking.
func EnumerateAnvilProcesses() ([]AnvilProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var procs []AnvilProcess
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		cmdBytes, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue // process went away, or /proc permission denied
		}
		if len(cmdBytes) == 0 {
			continue
		}

		// /proc/<pid>/cmdline uses NUL as argv separator.
		args := strings.Split(strings.TrimRight(string(cmdBytes), "\x00"), "\x00")
		if len(args) == 0 || args[0] != AnvilBinaryPath {
			continue
		}

		cfg := ""
		for i, a := range args {
			if a == "-config" && i+1 < len(args) {
				cfg = args[i+1]
				break
			}
		}

		procs = append(procs, AnvilProcess{
			PID:        pid,
			CmdLine:    strings.Join(args, " "),
			ConfigPath: cfg,
		})
	}
	return procs, nil
}

// EnumerateAnvilServices returns the systemd state of every anvil-*.service
// unit known to the system. Uses systemctl show for parseable output.
func EnumerateAnvilServices() ([]ServiceState, error) {
	// list-units --all catches both active and inactive units
	out, err := exec.Command("systemctl", "list-units", "--all", "--no-legend", "--plain", "anvil-*.service").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		if name == "" {
			continue
		}
		names = append(names, name)
	}

	// Fall back to the canonical pair if list-units returns nothing (older
	// systemd versions can be odd with glob matching).
	if len(names) == 0 {
		names = []string{"anvil-a", "anvil-b"}
	}

	var states []ServiceState
	for _, n := range names {
		st, err := getServiceState(n)
		if err != nil {
			continue // unit doesn't exist — just skip
		}
		states = append(states, st)
	}
	return states, nil
}

// FindOrphans returns anvil processes that are NOT the MainPID of any known
// anvil-*.service unit. These are the ones that cause lock-contention crash
// loops after upgrades or manual restarts.
func FindOrphans() ([]AnvilProcess, error) {
	procs, err := EnumerateAnvilProcesses()
	if err != nil {
		return nil, err
	}
	svcs, err := EnumerateAnvilServices()
	if err != nil {
		return nil, err
	}

	tracked := make(map[int]bool)
	for _, s := range svcs {
		if s.MainPID > 0 {
			tracked[s.MainPID] = true
		}
	}

	var orphans []AnvilProcess
	for _, p := range procs {
		if !tracked[p.PID] {
			orphans = append(orphans, p)
		}
	}
	return orphans, nil
}

// FindLockHolders scans a data directory (e.g. /var/lib/anvil) for LevelDB
// LOCK files and returns the PIDs currently holding them. Used by doctor to
// distinguish "store is locked by my own service" from "store is locked by
// an orphan I need to kill."
func FindLockHolders(dataDir string) ([]LockHolder, error) {
	var holders []LockHolder
	// LevelDB LOCK files live at <dir>/<store>/LOCK for each subsystem.
	stores := []string{"headers", "proofs", "envelopes", "overlay", "wallet", "invoices"}
	for _, s := range stores {
		lock := filepath.Join(dataDir, s, "LOCK")
		if _, err := os.Stat(lock); err != nil {
			continue // store not initialized yet
		}
		// fuser -s prints the PIDs holding any open handles on the file.
		// It exits non-zero when nobody holds it, which is the common case.
		out, err := exec.Command("fuser", lock).CombinedOutput()
		if err != nil || len(out) == 0 {
			continue
		}
		for _, pidStr := range strings.Fields(string(out)) {
			pidStr = strings.TrimSuffix(pidStr, "e") // fuser annotates "e" for exec access
			pidStr = strings.TrimSuffix(pidStr, "c")
			pidStr = strings.TrimSuffix(pidStr, "w")
			pidStr = strings.TrimSuffix(pidStr, "r")
			pid, err := strconv.Atoi(pidStr)
			if err != nil || pid <= 0 {
				continue
			}
			cmd := ""
			if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); err == nil {
				cmd = strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ")
			}
			holders = append(holders, LockHolder{LockFile: lock, PID: pid, CmdLine: cmd})
		}
	}
	return holders, nil
}

// IsCrashLooping returns true if the service's NRestarts counter has crossed
// the "definitely a problem" threshold. The default threshold is conservative
// enough that a healthy node, even after a few days of uptime with the
// occasional transient failure, won't trip it.
func IsCrashLooping(s ServiceState) bool {
	return s.NRestarts > 10
}

// KillOrphan sends SIGTERM to an orphan process and waits up to 5 seconds for
// it to exit. If it refuses, escalates to SIGKILL and waits another 2 seconds.
// Returns nil if the process is no longer running when the function returns.
func KillOrphan(p AnvilProcess) error {
	proc, err := os.FindProcess(p.PID)
	if err != nil {
		return fmt.Errorf("find pid %d: %w", p.PID, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if err == os.ErrProcessDone {
			return nil
		}
		return fmt.Errorf("SIGTERM pid %d: %w", p.PID, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(p.PID) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Escalate
	_ = proc.Signal(syscall.SIGKILL)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(p.PID) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("pid %d ignored both SIGTERM and SIGKILL", p.PID)
}

// BinaryVersion reads the Version constant from the binary at path by running
// `<path> version`. Returns empty string on any error.
func BinaryVersion(path string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return ""
	}
	// Expect format like "anvil vX.Y.Z" or just "X.Y.Z"
	line := strings.TrimSpace(string(out))
	for _, tok := range strings.Fields(line) {
		tok = strings.TrimPrefix(tok, "v")
		if isSemverish(tok) {
			return tok
		}
	}
	return ""
}

// pidAlive returns true if /proc/<pid> still exists. Preferred over kill -0
// because it doesn't require send permission to the target process.
func pidAlive(pid int) bool {
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}

// getServiceState runs `systemctl show <name>` and parses the fields we need.
func getServiceState(name string) (ServiceState, error) {
	out, err := exec.Command("systemctl", "show",
		"--property=ActiveState,SubState,NRestarts,MainPID",
		name+".service").Output()
	if err != nil {
		return ServiceState{}, err
	}
	st := ServiceState{Name: name, ActiveState: "unknown"}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			st.ActiveState = v
		case "SubState":
			st.SubState = v
		case "NRestarts":
			if n, err := strconv.Atoi(v); err == nil {
				st.NRestarts = n
			}
		case "MainPID":
			if n, err := strconv.Atoi(v); err == nil {
				st.MainPID = n
			}
		}
	}
	return st, nil
}

// isSemverish returns true for strings that look like a semver core (N.N.N).
func isSemverish(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts[:3] { // tolerate pre-release/build suffix on last
		if p == "" {
			return false
		}
		// trim any non-digit suffix (e.g. "0-rc1")
		for i, c := range p {
			if c < '0' || c > '9' {
				if i == 0 {
					return false
				}
				break
			}
		}
	}
	// require a digit in each of the first two
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}
