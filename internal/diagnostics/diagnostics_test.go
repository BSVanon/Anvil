package diagnostics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestEnumerateAnvilProcesses_NoneRunning verifies the happy path where no
// anvil processes are present on the system (the test's own host, usually).
// Since we override AnvilBinaryPath to a path that definitely isn't running
// anywhere, the result must be empty.
func TestEnumerateAnvilProcesses_NoneRunning(t *testing.T) {
	save := AnvilBinaryPath
	AnvilBinaryPath = "/nonexistent/path/to/anvil-for-test"
	t.Cleanup(func() { AnvilBinaryPath = save })

	procs, err := EnumerateAnvilProcesses()
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(procs) != 0 {
		t.Errorf("expected no processes, got %d", len(procs))
	}
}

// TestEnumerateAnvilProcesses_DetectsMatchingBinary creates a fake "anvil"
// binary as a shell script, starts it in the background, and verifies the
// probe picks it up via /proc cmdline scan. This is the critical path that
// keeps orphan detection honest.
func TestEnumerateAnvilProcesses_DetectsMatchingBinary(t *testing.T) {
	if _, err := os.Stat("/proc"); err != nil {
		t.Skip("/proc not available — not Linux?")
	}

	tmp := t.TempDir()
	fakeBin := filepath.Join(tmp, "anvil") // path we want to appear in /proc/pid/cmdline[0]
	fakeCfg := filepath.Join(tmp, "node-test.toml")

	// Spawn a process whose argv is [fakeBin, "-config", fakeCfg, ...trailing sleeper].
	// /proc/<pid>/cmdline reflects argv verbatim — so the scan sees fakeBin as
	// argv[0] and the config parser sees -config fakeCfg in the rest.
	// The actual exec target is /bin/sh with -c to stay alive without
	// interpreting our anvil-style flags.
	cmd := &exec.Cmd{
		Path: "/bin/sh",
		// argv[0]=fakeBin, [1]=-config, [2]=fakeCfg, then sh needs its own
		// -c <script> AFTER the dummy anvil flags. sh treats the first "-"
		// arg as its first flag, so "-config" would confuse it. Use --
		// to terminate sh option parsing, then the sentinel script.
		//
		// Actually simpler: put sh's -c first in argv[1:], then tack the
		// anvil-style flags onto the script's positional params ($0, $1...).
		// The cmdline seen by /proc is the full argv regardless.
		Args: []string{fakeBin, "-c", "sleep 30", fakeBin, "-config", fakeCfg},
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	save := AnvilBinaryPath
	AnvilBinaryPath = fakeBin
	t.Cleanup(func() { AnvilBinaryPath = save })

	// /proc cmdline may take a moment to settle
	var found *AnvilProcess
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		procs, err := EnumerateAnvilProcesses()
		if err != nil {
			t.Fatal(err)
		}
		for i := range procs {
			if procs[i].PID == cmd.Process.Pid {
				found = &procs[i]
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if found == nil {
		t.Fatal("spawned fake anvil process was not detected by EnumerateAnvilProcesses")
	}
	if found.ConfigPath != fakeCfg {
		t.Errorf("config path not parsed: got %q, want %q", found.ConfigPath, fakeCfg)
	}
}

// TestFindOrphans_SpawnedProcessIsOrphan verifies the orphan-detection core
// contract: a process running AnvilBinaryPath that is NOT the MainPID of any
// systemd unit gets flagged as an orphan. This is exactly the condition that
// caused the 12-day crash-loop on the production VPS.
func TestFindOrphans_SpawnedProcessIsOrphan(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl not on PATH — skipping")
	}

	tmp := t.TempDir()
	fakeBin := filepath.Join(tmp, "anvil")

	// argv[0] = fakeBin so the scan matches it; real exec target is /bin/sh
	cmd := &exec.Cmd{
		Path: "/bin/sh",
		Args: []string{fakeBin, "-c", "sleep 30"},
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	save := AnvilBinaryPath
	AnvilBinaryPath = fakeBin
	t.Cleanup(func() { AnvilBinaryPath = save })

	// Give /proc cmdline a moment to be populated
	time.Sleep(200 * time.Millisecond)

	orphans, err := FindOrphans()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range orphans {
		if o.PID == cmd.Process.Pid {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("spawned process not flagged as orphan — got %d orphans, none matched pid %d",
			len(orphans), cmd.Process.Pid)
	}
}

// TestKillOrphan_SIGTERMGraceful verifies that KillOrphan terminates a
// well-behaved process via SIGTERM and returns nil.
func TestKillOrphan_SIGTERMGraceful(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	orphan := AnvilProcess{PID: cmd.Process.Pid, CmdLine: "sleep 60"}

	// Async wait to reap the child (sleep exits cleanly on SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if err := KillOrphan(orphan); err != nil {
		t.Errorf("KillOrphan: %v", err)
	}

	select {
	case <-done:
		// expected — process reaped after SIGTERM
	case <-time.After(3 * time.Second):
		t.Error("process not reaped within 3s of KillOrphan")
	}
}

// TestKillOrphan_SIGKILLEscalation verifies KillOrphan successfully kills a
// process whose intermediate shell ignores SIGTERM. The implementation
// escalates to SIGKILL after the SIGTERM window; we assert the process is
// gone without pinning an exact timing window (shell signal delivery varies
// enough across distros that a strict threshold is flaky).
func TestKillOrphan_SIGKILLEscalation(t *testing.T) {
	// bash runs a loop that traps TERM into a no-op. The loop keeps bash in
	// user space (won't tail-exec into sleep) so SIGTERM is delivered to
	// bash itself and ignored.
	cmd := exec.Command("bash", "-c", `trap "" TERM; while :; do sleep 1; done`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	orphan := AnvilProcess{PID: cmd.Process.Pid, CmdLine: "bash (term-trap)"}

	if err := KillOrphan(orphan); err != nil {
		t.Errorf("KillOrphan: %v", err)
	}

	select {
	case <-done:
		// expected — process dead via SIGKILL escalation
	case <-time.After(10 * time.Second):
		t.Error("process survived both SIGTERM and SIGKILL — something is badly wrong")
	}
}

// TestFindLockHolders_ReportsLocker creates a directory with a LOCK file and
// a child process holding the file open, then verifies FindLockHolders picks
// it up. Guards the diagnostic that told us about the production orphan.
func TestFindLockHolders_ReportsLocker(t *testing.T) {
	if _, err := exec.LookPath("fuser"); err != nil {
		t.Skip("fuser not installed — skipping")
	}

	tmp := t.TempDir()
	storeDir := filepath.Join(tmp, "proofs")
	if err := os.Mkdir(storeDir, 0755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(storeDir, "LOCK")
	if err := os.WriteFile(lockPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	// Start a process that holds the lock file open (sleep on a piped FD)
	cmd := exec.Command("bash", "-c", "exec 9< "+lockPath+"; sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	})

	// Give the shell a moment to open the FD
	time.Sleep(200 * time.Millisecond)

	holders, err := FindLockHolders(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) == 0 {
		t.Fatal("expected at least one lock holder, got 0")
	}
	found := false
	for _, h := range holders {
		if h.LockFile == lockPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("LOCK holder not returned; got %+v", holders)
	}
}

// TestIsCrashLooping_ThresholdBoundary guards the threshold choice. If we
// later tune it, the test tells us what we changed.
func TestIsCrashLooping_ThresholdBoundary(t *testing.T) {
	cases := []struct {
		n    int
		want bool
	}{
		{0, false},
		{1, false},
		{10, false}, // at threshold — not yet crash-looping
		{11, true},  // first value that trips
		{1000, true},
	}
	for _, c := range cases {
		got := IsCrashLooping(ServiceState{NRestarts: c.n})
		if got != c.want {
			t.Errorf("NRestarts=%d: got %v, want %v", c.n, got, c.want)
		}
	}
}

// TestBinaryVersion_ParsesSemver verifies BinaryVersion extracts a semver
// from stdout of `<bin> version`. Uses a stub script that prints the
// expected format.
func TestBinaryVersion_ParsesSemver(t *testing.T) {
	tmp := t.TempDir()
	stub := filepath.Join(tmp, "fake-anvil")
	const script = `#!/bin/sh
echo "anvil v2.2.0"
`
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	got := BinaryVersion(stub)
	if got != "2.2.0" {
		t.Errorf("BinaryVersion = %q, want 2.2.0", got)
	}
}

// TestBinaryVersion_MissingFile returns empty string, not an error, so
// callers can use this as a graceful "unknown version" signal without
// breaking the diagnostic flow.
func TestBinaryVersion_MissingFile(t *testing.T) {
	got := BinaryVersion("/nonexistent/anvil-binary-" + strconv.Itoa(int(time.Now().UnixNano())))
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}
