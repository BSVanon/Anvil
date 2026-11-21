package main

import (
	"fmt"
	"io/fs"
	"math"
	"runtime/debug"
	"strings"
	"testing"
)

// files is a fake file system for chooseMemoryLimit.
type files map[string]string

func (f files) read(name string) ([]byte, error) {
	if s, ok := f[name]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

const meminfo8G = "MemTotal:        8388608 kB\nMemFree:         1234 kB\n"

// TestChooseMemoryLimit: 70% of the least memory.max on the process's cgroup
// v2 path, or, when v2 sets none, of the least memory.limit_in_bytes on its
// cgroup v1 path (the unlimited sentinel ignored, as v2's "max" is), or of
// the host's MemTotal when that is less or neither cgroup sets a limit;
// nothing when none of them can be read.
func TestChooseMemoryLimit(t *testing.T) {
	const service = "/sys/fs/cgroup/system.slice/anvil.service/memory.max"
	const slice = "/sys/fs/cgroup/system.slice/memory.max"
	for _, c := range []struct {
		name  string
		files files
		want  int64
		from  string
	}{
		{"the service's limit", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "2147483648\n", slice: "max\n", "/proc/meminfo": meminfo8G}, 2 << 30 / 100 * 70, service},
		{"a parent's lower limit", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "2147483648\n", slice: "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, slice},
		{"a container's root", files{"/proc/self/cgroup": "0::/\n", "/sys/fs/cgroup/memory.max": "536870912\n", "/proc/meminfo": meminfo8G}, 512 << 20 / 100 * 70, "/sys/fs/cgroup/memory.max"},
		{"no limit set", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "max\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"a limit over the host's memory", files{"/proc/self/cgroup": "0::/user.slice\n", "/sys/fs/cgroup/user.slice/memory.max": "68719476736\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"cgroup v1 only, nothing under it readable", files{"/proc/self/cgroup": "12:memory:/user.slice\n1:name=systemd:/user.slice\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"cgroup v1 with a limit", files{"/proc/self/cgroup": "12:memory:/user.slice/anvil\n1:name=systemd:/user.slice/anvil\n", "/sys/fs/cgroup/memory/user.slice/anvil/memory.limit_in_bytes": "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, "memory.limit_in_bytes"},
		{"cgroup v1, a parent's lower limit", files{"/proc/self/cgroup": "12:memory:/user.slice/anvil\n", "/sys/fs/cgroup/memory/user.slice/anvil/memory.limit_in_bytes": "2147483648\n", "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes": "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, "user.slice/memory.limit_in_bytes"},
		{"cgroup v1 combined controllers", files{"/proc/self/cgroup": "4:cpu,memory:/docker/abc\n", "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes": "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, "memory.limit_in_bytes"},
		{"cgroup v1 unlimited sentinel ignored", files{"/proc/self/cgroup": "12:memory:/user.slice\n", "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes": "9223372036854771712\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		// With no host meminfo to fall back to, a wrongly-accepted sentinel
		// would surface as a many-exabyte limit instead of none: unlike the
		// case above, the host's smaller MemTotal cannot mask the bug here.
		{"cgroup v1 unlimited sentinel ignored, no host fallback to mask it", files{"/proc/self/cgroup": "12:memory:/user.slice\n", "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes": "9223372036854771712\n"}, 0, ""},
		{"hybrid: v2 line present but unset falls back to v1's limit", files{"/proc/self/cgroup": "1:memory:/user.slice\n0::/system.slice/anvil.service\n", "/sys/fs/cgroup/system.slice/anvil.service/memory.max": "max\n", "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes": "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, "memory.limit_in_bytes"},
		{"no /proc/self/cgroup", files{"/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"nothing readable", files{}, 0, ""},
		{"an unreadable meminfo", files{"/proc/meminfo": "MemTotal: lots\n"}, 0, ""},
	} {
		got, of := chooseMemoryLimit(c.files.read)
		if got != c.want || !strings.Contains(of, c.from) {
			t.Errorf("%s: %d from %q, want %d from %q", c.name, got, of, c.want, c.from)
		}
	}
}

// TestApplyMemoryLimit: unset, GOMEMLIMIT is chosen, applied and logged; set,
// it wins, and the limit the runtime took from it is left alone.
func TestApplyMemoryLimit(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })
	fake := files{"/proc/meminfo": meminfo8G}
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	applyMemoryLimit(func(string) string { return "" }, fake.read, logf)
	want := int64(8 << 30 / 100 * 70)
	if got := debug.SetMemoryLimit(-1); got != want {
		t.Fatalf("unset GOMEMLIMIT: the limit is %d, want %d", got, want)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "5.60 GiB, 70% of the host's memory (8.00 GiB)") {
		t.Fatalf("logged %q", logged)
	}

	debug.SetMemoryLimit(math.MaxInt64)
	logged = nil
	applyMemoryLimit(func(k string) string {
		if k == "GOMEMLIMIT" {
			return "off"
		}
		return ""
	}, fake.read, logf)
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Fatalf("GOMEMLIMIT=off: the limit was changed to %d", got)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "off, from GOMEMLIMIT") {
		t.Fatalf("logged %q", logged)
	}

	logged = nil
	applyMemoryLimit(func(string) string { return "" }, files{}.read, logf)
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 || len(logged) != 1 || !strings.Contains(logged[0], "none") {
		t.Fatalf("nothing readable: limit %d, logged %q", got, logged)
	}
}

// TestApplyMemoryLimit_WarnsBelowTheGuardsBudget verifies the warning when
// 11): a chosen limit under the route guard's own MemoryBudget plus
// ExecAllowance is warned about once, whether it came from a small cgroup
// limit or directly from GOMEMLIMIT; a limit at or over that floor is not.
func TestApplyMemoryLimit_WarnsBelowTheGuardsBudget(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	// A cgroup limit that leaves less than budgetFloor once reduced to
	// memoryLimitPercent.
	const cgroupLimit = 600 << 20
	low := files{"/proc/self/cgroup": "0::/x\n", "/sys/fs/cgroup/x/memory.max": fmt.Sprintf("%d\n", cgroupLimit), "/proc/meminfo": meminfo8G}
	wantLow := int64(cgroupLimit / 100 * memoryLimitPercent)
	if wantLow >= budgetFloor {
		t.Fatalf("test fixture is wrong: %d is not under budgetFloor %d", wantLow, budgetFloor)
	}
	applyMemoryLimit(func(string) string { return "" }, low.read, logf)
	if got := debug.SetMemoryLimit(-1); got != wantLow {
		t.Fatalf("a cgroup limit under the guard's budget: the limit is %d, want %d", got, wantLow)
	}
	if len(logged) != 2 || !strings.Contains(logged[1], "below the overlay guard's own budget") {
		t.Fatalf("a limit under the guard's budget was not warned about once: %q", logged)
	}

	// A limit at or over budgetFloor is not warned about (the unset-GOMEMLIMIT
	// case covered by TestApplyMemoryLimit, 5.60 GiB, already shows this, but
	// assert it here beside the low case for contrast).
	logged = nil
	applyMemoryLimit(func(string) string { return "" }, files{"/proc/meminfo": meminfo8G}.read, logf)
	if len(logged) != 1 {
		t.Fatalf("a limit over the guard's budget was warned about: %q", logged)
	}

	// GOMEMLIMIT itself set below the floor: the runtime has already applied
	// it by the time applyMemoryLimit runs, so the fake env var's value is
	// cosmetic here and the pre-set runtime limit is what is read back and
	// judged.
	const envLimit = 300 << 20
	if envLimit >= budgetFloor {
		t.Fatalf("test fixture is wrong: %d is not under budgetFloor %d", int64(envLimit), budgetFloor)
	}
	debug.SetMemoryLimit(envLimit)
	logged = nil
	applyMemoryLimit(func(k string) string {
		if k == "GOMEMLIMIT" {
			return "300MiB"
		}
		return ""
	}, files{}.read, logf)
	if got := debug.SetMemoryLimit(-1); got != envLimit {
		t.Fatalf("GOMEMLIMIT set: the limit was changed to %d", got)
	}
	if len(logged) != 2 || !strings.Contains(logged[0], "300MiB, from GOMEMLIMIT") || !strings.Contains(logged[1], "below the overlay guard's own budget") {
		t.Fatalf("a low GOMEMLIMIT was not warned about once: %q", logged)
	}
}
